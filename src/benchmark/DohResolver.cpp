#include "benchmark/DohResolver.h"

#include "benchmark/DnsPacket.h"

#include <QElapsedTimer>
#include <QNetworkReply>
#include <QNetworkRequest>
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
    const quint16 transactionId = 0;
    const QByteArray queryPacket = DnsPacket::buildQuery(domain, transactionId, 1);
    if (queryPacket.isEmpty() || !endpoint().isValid()) {
        callback(0, false);
        return;
    }

    QNetworkRequest request(endpoint());
    request.setHeader(QNetworkRequest::ContentTypeHeader, QStringLiteral("application/dns-message"));
    request.setRawHeader("Accept", "application/dns-message");
    request.setTransferTimeout(m_timeoutMs);

    auto elapsed = std::make_shared<QElapsedTimer>();
    elapsed->start();
    QNetworkReply* reply = m_network.post(request, queryPacket);

    QObject::connect(reply, &QNetworkReply::finished, reply, [reply, transactionId, elapsed, callback = std::move(callback)]() mutable {
        const QByteArray payload = reply->readAll();
        const bool success = reply->error() == QNetworkReply::NoError && DnsPacket::isValidResponse(payload, transactionId);
        const qint64 rtt = success ? elapsed->elapsed() : 0;
        reply->deleteLater();
        callback(rtt, success);
    });
}
