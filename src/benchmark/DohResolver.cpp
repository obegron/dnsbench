#include "benchmark/DohResolver.h"

#include "benchmark/DnsPacket.h"

#include <QElapsedTimer>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSslError>
#include <QStringList>
#include <QTimer>

#include <memory>

DohResolver::DohResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
    : BaseResolver(parent)
    , m_entry(entry)
    , m_timeoutMs(timeoutMs)
    , m_network(this)
{
}

QString DohResolver::id() const
{
    return m_entry.id;
}

void DohResolver::setTimeoutMs(int timeoutMs)
{
    m_timeoutMs = timeoutMs;
}

QString DohResolver::lastErrorString() const
{
    return m_lastError;
}

QUrl DohResolver::endpoint() const
{
    QUrl url(m_entry.address);
    if (url.scheme().isEmpty()) {
        url = QUrl(QStringLiteral("https://%1/dns-query").arg(m_entry.address));
    }
    return url;
}

void DohResolver::query(const QString& domain, QueryCallback callback)
{
    m_lastError.clear();
    const quint16 transactionId = 0;
    const QByteArray queryPacket = DnsPacket::buildQuery(domain, transactionId, 1);
    const QUrl url = endpoint();
    if (queryPacket.isEmpty()) {
        m_lastError = QStringLiteral("could not build DNS query for %1").arg(domain);
        callback(0, false);
        return;
    }
    if (!url.isValid()) {
        m_lastError = QStringLiteral("invalid DoH endpoint: %1").arg(m_entry.address);
        callback(0, false);
        return;
    }

    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/dns-message"));
    request.setRawHeader("Accept", "application/dns-message");
    request.setTransferTimeout(m_timeoutMs);

    auto elapsed = std::make_shared<QElapsedTimer>();
    elapsed->start();
    QNetworkReply* reply = m_network.post(request, queryPacket);

    QObject::connect(reply, &QNetworkReply::sslErrors, reply, [this](const QList<QSslError>& errors) {
        QStringList messages;
        messages.reserve(errors.size());
        for (const QSslError& error : errors) {
            messages.push_back(error.errorString());
        }
        m_lastError = QStringLiteral("TLS error: %1").arg(messages.join(QStringLiteral("; ")));
    });

    QObject::connect(reply, &QNetworkReply::finished, reply, [this, reply, transactionId, elapsed, callback = std::move(callback)]() mutable {
        const QByteArray payload = reply->readAll();
        const QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        bool success = false;
        if (reply->error() != QNetworkReply::NoError) {
            m_lastError = QStringLiteral("%1 (%2)").arg(reply->errorString()).arg(static_cast<int>(reply->error()));
        } else if (statusCode.isValid() && (statusCode.toInt() < 200 || statusCode.toInt() >= 300)) {
            m_lastError = QStringLiteral("HTTP %1 from %2").arg(statusCode.toInt()).arg(reply->url().toString());
        } else if (!DnsPacket::isValidResponse(payload, transactionId)) {
            m_lastError = QStringLiteral("invalid DNS message response from %1: %2 bytes").arg(reply->url().toString()).arg(payload.size());
        } else {
            success = true;
        }
        const qint64 rtt = success ? elapsed->elapsed() : 0;
        reply->deleteLater();
        callback(rtt, success);
    });
}
