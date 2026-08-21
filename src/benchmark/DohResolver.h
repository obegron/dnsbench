#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QByteArray>
#include <QFutureWatcher>
#include <QUrl>

#include <atomic>
#include <curl/curl.h>

class DohResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit DohResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);
    ~DohResolver() override;

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;
    void setTimeoutMs(int timeoutMs) override;
    QString lastErrorString() const override;
    QString lastQueryTransport() const override;
    bool lastAuthenticatedDataBit() const override;
    void cancel() override;
    QUrl endpoint() const;

private:
    struct CurlResult {
        QByteArray payload;
        QByteArray error;
        CURLcode code = CURLE_FAILED_INIT;
        long statusCode = 0;
        long httpVersion = CURL_HTTP_VERSION_NONE;
        curl_off_t elapsedUs = 0;
    };

    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
    QString m_lastError;
    QString m_lastQueryTransport;
    bool m_lastAuthenticatedDataBit = false;
    CURL* m_curl = nullptr;
    CURLM* m_multi = nullptr;
    curl_slist* m_headers = nullptr;
    QFutureWatcher<CurlResult> m_watcher;
    QueryCallback m_callback;
    QString m_domain;
    quint16 m_transactionId = 0;
    std::atomic_bool m_cancelled = false;

    CurlResult performQuery(QByteArray url, QByteArray queryPacket, int timeoutMs);
    void finishQuery();
};
