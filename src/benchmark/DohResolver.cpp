#include "benchmark/DohResolver.h"

#include "benchmark/DnsPacket.h"

#include <QHostAddress>
#include <QHostInfo>
#include <QElapsedTimer>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QRandomGenerator>
#include <QSslError>
#include <QStringList>
#include <QTimer>

#include <memory>

namespace {

QString resolutionHint(const QString& host)
{
    const QHostInfo info = QHostInfo::fromName(host);
    if (info.error() != QHostInfo::NoError) {
        return QStringLiteral(" Host lookup for %1 failed: %2.").arg(host, info.errorString());
    }

    QStringList addresses;
    bool sinkholeLike = false;
    for (const QHostAddress& address : info.addresses()) {
        const QString text = address.toString();
        addresses.push_back(text);
        if (text == QLatin1String("0.0.0.0") || text == QLatin1String("::")
            || text == QLatin1String("::1") || text.startsWith(QStringLiteral("127."))) {
            sinkholeLike = true;
        }
    }

    if (addresses.isEmpty()) {
        return QStringLiteral(" Host lookup for %1 returned no addresses.").arg(host);
    }

    return sinkholeLike
        ? QStringLiteral(" %1 resolves to %2, which looks like DNS blocking/sinkholing; allowlist this DoH hostname in your current DNS filter.")
              .arg(host, addresses.join(QStringLiteral(", ")))
        : QStringLiteral(" %1 resolves to %2. If this is a filtering or internal address, allowlist the DoH hostname.")
              .arg(host, addresses.join(QStringLiteral(", ")));
}

}

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

bool DohResolver::lastAuthenticatedDataBit() const
{
    return m_lastAuthenticatedDataBit;
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
    m_lastAuthenticatedDataBit = false;
    const quint16 transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
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

    QObject::connect(reply, &QNetworkReply::finished, reply, [this, reply, transactionId, domain, elapsed, callback = std::move(callback)]() mutable {
        const QByteArray payload = reply->readAll();
        const QVariant statusCode = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        bool success = false;
        if (reply->error() != QNetworkReply::NoError) {
            m_lastError = QStringLiteral("%1 (%2)%3")
                .arg(reply->errorString())
                .arg(static_cast<int>(reply->error()))
                .arg(resolutionHint(reply->url().host()));
        } else if (statusCode.isValid() && (statusCode.toInt() < 200 || statusCode.toInt() >= 300)) {
            m_lastError = QStringLiteral("HTTP %1 from %2").arg(statusCode.toInt()).arg(reply->url().toString());
        } else if (!DnsPacket::isValidResponse(payload, transactionId, domain, 1)) {
            m_lastError = QStringLiteral("invalid DNS message response from %1: %2 bytes").arg(reply->url().toString()).arg(payload.size());
        } else {
            m_lastAuthenticatedDataBit = DnsPacket::authenticatedDataBit(payload);
            success = true;
        }
        const qint64 rtt = success ? elapsed->elapsed() : 0;
        reply->deleteLater();
        callback(rtt, success);
    });
}
