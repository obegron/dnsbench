#include "benchmark/UdpResolver.h"

#include "benchmark/DnsPacket.h"

#include <QElapsedTimer>
#include <QPointer>
#include <QRandomGenerator>
#include <QTimer>
#include <QUdpSocket>

#include <memory>

UdpResolver::UdpResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
    : BaseResolver(parent)
    , m_entry(entry)
    , m_timeoutMs(timeoutMs)
{
}

QString UdpResolver::id() const
{
    return m_entry.id;
}

void UdpResolver::setTimeoutMs(int timeoutMs)
{
    m_timeoutMs = timeoutMs;
}

void UdpResolver::query(const QString& domain, QueryCallback callback)
{
    auto* socket = new QUdpSocket(this);
    auto* timeout = new QTimer(socket);
    timeout->setSingleShot(true);

    const quint16 transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
    const QByteArray queryPacket = DnsPacket::buildQuery(domain, transactionId, 1);
    const QHostAddress remote(m_entry.address);
    const QHostAddress bindAddress = m_entry.protocol == ResolverProtocol::IPv6
        ? QHostAddress::AnyIPv6
        : QHostAddress::AnyIPv4;

    auto elapsed = std::make_shared<QElapsedTimer>();
    auto completed = std::make_shared<bool>(false);

    auto finish = [socket, timeout, callback = std::move(callback), elapsed, completed](qint64 rttMs, bool success) mutable {
        if (*completed) {
            return;
        }
        *completed = true;
        timeout->stop();
        socket->close();
        socket->deleteLater();
        callback(rttMs, success);
    };

    if (queryPacket.isEmpty() || remote.isNull() || !socket->bind(bindAddress, 0)) {
        finish(0, false);
        return;
    }

    QObject::connect(timeout, &QTimer::timeout, socket, [finish]() mutable {
        finish(0, false);
    });

    QObject::connect(socket, &QUdpSocket::readyRead, socket, [socket, transactionId, elapsed, finish]() mutable {
        while (socket->hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(socket->pendingDatagramSize()));
            socket->readDatagram(datagram.data(), datagram.size());
            if (DnsPacket::isValidResponse(datagram, transactionId)) {
                finish(elapsed->elapsed(), true);
                return;
            }
        }
    });

    elapsed->start();
    timeout->start(m_timeoutMs);
    const qint64 written = socket->writeDatagram(queryPacket, remote, static_cast<quint16>(m_entry.port));
    if (written != queryPacket.size()) {
        finish(0, false);
    }
}
