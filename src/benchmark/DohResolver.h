#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QElapsedTimer>
#include <QNetworkAccessManager>
#include <QPointer>
#include <QUrl>

#include <memory>

class QNetworkReply;

class DohResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit DohResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;
    void setTimeoutMs(int timeoutMs) override;
    QString lastErrorString() const override;
    bool lastAuthenticatedDataBit() const override;
    void cancel() override;
    QUrl endpoint() const;

private:
    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
    QString m_lastError;
    bool m_lastAuthenticatedDataBit = false;
    QNetworkAccessManager m_network;
    QPointer<QNetworkReply> m_reply;

    void queryWithRetry(const QString& domain, QueryCallback callback, bool retryHttp2ProtocolError, std::shared_ptr<QElapsedTimer> elapsed);
};
