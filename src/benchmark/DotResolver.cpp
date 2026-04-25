#include "benchmark/DotResolver.h"

#include "benchmark/DnsPacket.h"

#include <QRandomGenerator>
#include <QSslError>
#include <QStringList>
#include <QtEndian>

DotResolver::DotResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
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

    connect(&m_socket, &QSslSocket::errorOccurred, this, [this](QAbstractSocket::SocketError) {
        if (m_queryInFlight) {
            m_lastError = m_socket.errorString();
            finish(0, false);
        }
    });

    connect(&m_socket, &QSslSocket::sslErrors, this, [this](const QList<QSslError>& errors) {
        QStringList messages;
        messages.reserve(errors.size());
        for (const QSslError& error : errors) {
            messages.push_back(error.errorString());
        }
        m_lastError = QStringLiteral("TLS error: %1").arg(messages.join(QStringLiteral("; ")));
        if (m_queryInFlight) {
            m_socket.abort();
            finish(0, false);
        }
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
        const bool valid = DnsPacket::isValidResponse(response, m_transactionId, m_expectedDomain, 1);
        m_lastAuthenticatedDataBit = valid && DnsPacket::authenticatedDataBit(response);
        if (!valid && m_lastError.isEmpty()) {
            m_lastError = QStringLiteral("invalid DNS response for %1").arg(m_expectedDomain);
        }
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

QString DotResolver::lastErrorString() const
{
    return m_lastError;
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

    m_lastError.clear();
    m_lastAuthenticatedDataBit = false;
    m_transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
    m_expectedDomain = domain;
    const QByteArray dnsPacket = DnsPacket::buildQuery(domain, m_transactionId, 1);
    if (dnsPacket.isEmpty()) {
        m_lastError = QStringLiteral("could not build DNS query for %1").arg(domain);
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
    m_lastError = QStringLiteral("cancelled");
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
