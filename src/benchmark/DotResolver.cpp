#include "benchmark/DotResolver.h"

#include "benchmark/DnsPacket.h"

#include <QRandomGenerator>
#include <QtEndian>

DotResolver::DotResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
    : BaseResolver(parent)
    , m_entry(entry)
    , m_timeoutMs(timeoutMs)
{
    m_timeout.setSingleShot(true);
    m_timeout.setInterval(m_timeoutMs);
    connect(&m_timeout, &QTimer::timeout, this, [this]() {
        finish(0, false);
    });

    connect(&m_socket, &QSslSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (m_queryInFlight) {
            finish(0, false);
        }
    });

    connect(&m_socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError>& errors) {
        Q_UNUSED(errors);
        m_socket.ignoreSslErrors();
    });

    connect(&m_socket, &QSslSocket::readyRead, this, [this]() {
        m_buffer.append(m_socket.readAll());
        if (m_buffer.size() < 2) {
            return;
        }
        const quint16 length = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(m_buffer.constData()));
        if (m_buffer.size() < 2 + length) {
            return;
        }
        const QByteArray response = m_buffer.mid(2, length);
        const bool valid = DnsPacket::isValidResponse(response, m_transactionId);
        m_lastAuthenticatedDataBit = valid && DnsPacket::authenticatedDataBit(response);
        finish(valid ? m_elapsed.elapsed() : 0, valid);
    });
}

QString DotResolver::id() const
{
    return m_entry.id;
}

void DotResolver::setTimeoutMs(int timeoutMs)
{
    m_timeoutMs = timeoutMs;
    m_timeout.setInterval(m_timeoutMs);
}

bool DotResolver::lastAuthenticatedDataBit() const
{
    return m_lastAuthenticatedDataBit;
}

void DotResolver::query(const QString& domain, QueryCallback callback)
{
    if (m_queryInFlight) {
        callback(0, false);
        return;
    }

    m_lastAuthenticatedDataBit = false;
    m_transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
    const QByteArray dnsPacket = DnsPacket::buildQuery(domain, m_transactionId, 1);
    if (dnsPacket.isEmpty()) {
        callback(0, false);
        return;
    }

    m_callback = std::move(callback);
    m_queryInFlight = true;
    m_buffer.clear();

    if (m_socket.state() == QAbstractSocket::ConnectedState && m_socket.isEncrypted()) {
        sendCurrentQuery(dnsPacket);
        return;
    }

    const auto connection = std::make_shared<QMetaObject::Connection>();
    *connection = connect(&m_socket, &QSslSocket::encrypted, this, [this, dnsPacket, connection]() {
        disconnect(*connection);
        sendCurrentQuery(dnsPacket);
    });
    m_timeout.start(m_timeoutMs);
    m_socket.connectToHostEncrypted(m_entry.address, static_cast<quint16>(m_entry.port));
}

void DotResolver::cancel()
{
    finish(0, false);
}

void DotResolver::sendCurrentQuery(const QByteArray& dnsPacket)
{
    if (!m_queryInFlight) {
        return;
    }

    QByteArray framed;
    const quint16 beLength = qToBigEndian(static_cast<quint16>(dnsPacket.size()));
    framed.append(reinterpret_cast<const char*>(&beLength), sizeof(beLength));
    framed.append(dnsPacket);

    m_elapsed.restart();
    m_timeout.start(m_timeoutMs);
    if (m_socket.write(framed) != framed.size()) {
        finish(0, false);
    }
}

void DotResolver::finish(qint64 rttMs, bool success)
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
