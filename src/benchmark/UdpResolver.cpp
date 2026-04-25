#include "benchmark/UdpResolver.h"

#include "benchmark/DnsPacket.h"

#include <QElapsedTimer>
#include <QRandomGenerator>
#include <QTimer>
#include <QUdpSocket>

UdpResolver::UdpResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
    : BaseResolver(parent)
    , m_entry(entry)
    , m_timeoutMs(timeoutMs)
{
    m_timeout.setSingleShot(true);
    m_timeout.setInterval(m_timeoutMs);
    connect(&m_timeout, &QTimer::timeout, this, [this]() {
        m_lastError = QStringLiteral("timeout after %1 ms").arg(m_timeoutMs);
        finish(0, false);
    });

    connect(&m_socket, &QUdpSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (m_queryInFlight) {
            m_lastError = m_socket.errorString();
            finish(0, false);
        }
    });

    connect(&m_socket, &QUdpSocket::readyRead, this, [this]() {
        while (m_socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(m_socket.pendingDatagramSize()));
            m_socket.readDatagram(datagram.data(), datagram.size());
            if (!DnsPacket::hasExpectedResponseId(datagram, m_transactionId)) {
                continue;
            }
            if (!DnsPacket::isValidResponse(datagram, m_transactionId, m_expectedDomain, 1)) {
                m_lastError = QStringLiteral("invalid DNS response for %1").arg(m_expectedDomain);
                finish(0, false);
                return;
            }
            m_lastAuthenticatedDataBit = DnsPacket::authenticatedDataBit(datagram);
            finish(m_elapsed.elapsed(), true);
            return;
        }
    });
}

QString UdpResolver::id() const
{
    return m_entry.id;
}

void UdpResolver::setTimeoutMs(int timeoutMs)
{
    m_timeoutMs = timeoutMs;
    m_timeout.setInterval(m_timeoutMs);
}

QString UdpResolver::lastErrorString() const
{
    return m_lastError;
}

bool UdpResolver::lastAuthenticatedDataBit() const
{
    return m_lastAuthenticatedDataBit;
}

void UdpResolver::query(const QString& domain, QueryCallback callback)
{
    if (m_queryInFlight) {
        callback(0, false);
        return;
    }

    m_lastError.clear();
    m_lastAuthenticatedDataBit = false;
    m_transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
    m_expectedDomain = domain;
    const QByteArray queryPacket = DnsPacket::buildQuery(domain, m_transactionId, 1);
    const QHostAddress remote(m_entry.address);

    if (queryPacket.isEmpty()) {
        m_lastError = QStringLiteral("could not build DNS query for %1").arg(domain);
        callback(0, false);
        return;
    }
    if (remote.isNull()) {
        m_lastError = QStringLiteral("invalid UDP resolver address: %1").arg(m_entry.address);
        callback(0, false);
        return;
    }
    if (!ensureBound()) {
        callback(0, false);
        return;
    }

    while (m_socket.hasPendingDatagrams()) {
        QByteArray staleDatagram;
        staleDatagram.resize(static_cast<int>(m_socket.pendingDatagramSize()));
        m_socket.readDatagram(staleDatagram.data(), staleDatagram.size());
    }

    m_callback = std::move(callback);
    m_queryInFlight = true;
    m_elapsed.restart();
    m_timeout.start(m_timeoutMs);
    const qint64 written = m_socket.writeDatagram(queryPacket, remote, static_cast<quint16>(m_entry.port));
    if (written != queryPacket.size()) {
        m_lastError = m_socket.errorString().isEmpty()
            ? QStringLiteral("short UDP write to %1").arg(m_entry.address)
            : m_socket.errorString();
        finish(0, false);
    }
}

void UdpResolver::cancel()
{
    m_lastError = QStringLiteral("cancelled");
    finish(0, false);
}

bool UdpResolver::ensureBound()
{
    if (m_socket.state() == QAbstractSocket::BoundState) {
        return true;
    }

    const QHostAddress bindAddress = m_entry.protocol == ResolverProtocol::IPv6
        ? QHostAddress::AnyIPv6
        : QHostAddress::AnyIPv4;
    if (!m_socket.bind(bindAddress, 0)) {
        m_lastError = QStringLiteral("could not bind UDP socket: %1").arg(m_socket.errorString());
        return false;
    }
    return true;
}

void UdpResolver::finish(qint64 rttMs, bool success)
{
    if (!m_queryInFlight) {
        return;
    }

    m_timeout.stop();
    m_queryInFlight = false;
    QueryCallback callback = std::move(m_callback);
    m_callback = {};
    if (callback) {
        callback(rttMs, success);
    }
}
