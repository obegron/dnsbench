#include "benchmark/DohResolver.h"

#include "benchmark/DnsPacket.h"

#include <QHostAddress>
#include <QHostInfo>
#include <QRandomGenerator>
#include <QStringList>
#include <QtConcurrentRun>

#include <limits>
#include <mutex>
#include <utility>

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
        : QStringLiteral(" Host lookup for %1 returned %2.")
              .arg(host, addresses.join(QStringLiteral(", ")));
}

size_t appendResponse(char* data, size_t size, size_t count, void* target)
{
    if (size != 0 && count > std::numeric_limits<size_t>::max() / size) {
        return 0;
    }
    const size_t bytes = size * count;
    auto* payload = static_cast<QByteArray*>(target);
    if (bytes > static_cast<size_t>(std::numeric_limits<qsizetype>::max() - payload->size())) {
        return 0;
    }
    payload->append(data, static_cast<qsizetype>(bytes));
    return bytes;
}

int transferProgress(void* cancelled, curl_off_t, curl_off_t, curl_off_t, curl_off_t)
{
    return static_cast<std::atomic_bool*>(cancelled)->load(std::memory_order_relaxed) ? 1 : 0;
}

bool retryableHttp2Error(CURLcode code)
{
    return code == CURLE_HTTP2 || code == CURLE_HTTP2_STREAM;
}

QString transportName(long version)
{
    switch (version) {
    case CURL_HTTP_VERSION_2_0:
        return QStringLiteral("HTTP/2");
    case CURL_HTTP_VERSION_1_0:
        return QStringLiteral("HTTP/1.0");
    case CURL_HTTP_VERSION_1_1:
        return QStringLiteral("HTTP/1.1");
    default:
        return QStringLiteral("HTTP/unknown");
    }
}

bool initializeCurl()
{
    static std::once_flag once;
    static CURLcode result = CURLE_FAILED_INIT;
    std::call_once(once, []() {
        result = curl_global_init(CURL_GLOBAL_DEFAULT);
    });
    return result == CURLE_OK;
}

}

DohResolver::DohResolver(const ResolverEntry& entry, int timeoutMs, QObject* parent)
    : BaseResolver(parent)
    , m_entry(entry)
    , m_timeoutMs(timeoutMs)
{
    if (initializeCurl()) {
        m_curl = curl_easy_init();
        m_multi = curl_multi_init();
        if (!m_curl || !m_multi) {
            if (m_curl) {
                curl_easy_cleanup(m_curl);
                m_curl = nullptr;
            }
            if (m_multi) {
                curl_multi_cleanup(m_multi);
                m_multi = nullptr;
            }
        }
    }
    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/dns-message");
    if (headers) {
        curl_slist* completeHeaders = curl_slist_append(headers, "Accept: application/dns-message");
        if (completeHeaders) {
            m_headers = completeHeaders;
        } else {
            curl_slist_free_all(headers);
        }
    }

    QObject::connect(&m_watcher, &QFutureWatcher<CurlResult>::finished, this, &DohResolver::finishQuery);
}

DohResolver::~DohResolver()
{
    cancel();
    m_watcher.waitForFinished();
    if (m_curl) {
        curl_easy_cleanup(m_curl);
    }
    if (m_multi) {
        curl_multi_cleanup(m_multi);
    }
    curl_slist_free_all(m_headers);
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

QString DohResolver::lastQueryTransport() const
{
    return m_lastQueryTransport;
}

bool DohResolver::lastAuthenticatedDataBit() const
{
    return m_lastAuthenticatedDataBit;
}

void DohResolver::cancel()
{
    m_cancelled.store(true, std::memory_order_relaxed);
    m_lastError = QStringLiteral("cancelled");
    if (m_multi) {
        curl_multi_wakeup(m_multi);
    }
}

QUrl DohResolver::endpoint() const
{
    QUrl url(m_entry.address);
    if (url.scheme().isEmpty()) {
        url = QUrl(QStringLiteral("https://%1/dns-query").arg(m_entry.address));
    }
    if (!url.isValid() || url.scheme() != QLatin1String("https") || url.host().isEmpty()) {
        return {};
    }
    if (url.port() < 0 && m_entry.port >= 1 && m_entry.port <= 65535) {
        url.setPort(m_entry.port);
    }
    return url;
}

void DohResolver::query(const QString& domain, QueryCallback callback)
{
    m_lastError.clear();
    m_lastQueryTransport.clear();
    m_lastAuthenticatedDataBit = false;

    const quint16 transactionId = static_cast<quint16>(QRandomGenerator::global()->bounded(1, 0xffff));
    const QByteArray queryPacket = DnsPacket::buildQuery(domain, transactionId, 1);
    const QUrl url = endpoint();
    if (queryPacket.isEmpty()) {
        m_lastError = QStringLiteral("could not build DNS query for %1").arg(domain);
        callback(0.0, false);
        return;
    }
    if (!url.isValid() || url.isEmpty()) {
        m_lastError = QStringLiteral("invalid DoH endpoint (HTTPS is required): %1").arg(m_entry.address);
        callback(0.0, false);
        return;
    }
    if (!m_curl || !m_multi || !m_headers) {
        m_lastError = QStringLiteral("could not initialize the libcurl DoH transport");
        callback(0.0, false);
        return;
    }
    if (m_watcher.isRunning()) {
        m_lastError = QStringLiteral("a DoH query is already in progress");
        callback(0.0, false);
        return;
    }

    m_cancelled.store(false, std::memory_order_relaxed);
    m_callback = std::move(callback);
    m_domain = domain;
    m_transactionId = transactionId;
    const QByteArray encodedUrl = url.toEncoded(QUrl::FullyEncoded);
    const int timeoutMs = m_timeoutMs;
    m_watcher.setFuture(QtConcurrent::run([this, encodedUrl, queryPacket, timeoutMs]() {
        return performQuery(encodedUrl, queryPacket, timeoutMs);
    }));
}

DohResolver::CurlResult DohResolver::performQuery(QByteArray url, QByteArray queryPacket, int timeoutMs)
{
    CurlResult result;
    char errorBuffer[CURL_ERROR_SIZE] = {};

    curl_easy_setopt(m_curl, CURLOPT_URL, url.constData());
    curl_easy_setopt(m_curl, CURLOPT_HTTPHEADER, m_headers);
    curl_easy_setopt(m_curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2TLS);
    curl_easy_setopt(m_curl, CURLOPT_POST, 1L);
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDS, queryPacket.constData());
    curl_easy_setopt(m_curl, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(queryPacket.size()));
    curl_easy_setopt(m_curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(m_curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, appendResponse);
    curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &result.payload);
    curl_easy_setopt(m_curl, CURLOPT_NOPROGRESS, 0L);
    curl_easy_setopt(m_curl, CURLOPT_XFERINFOFUNCTION, transferProgress);
    curl_easy_setopt(m_curl, CURLOPT_XFERINFODATA, &m_cancelled);
    curl_easy_setopt(m_curl, CURLOPT_ERRORBUFFER, errorBuffer);
    curl_easy_setopt(m_curl, CURLOPT_FRESH_CONNECT, 0L);
    curl_easy_setopt(m_curl, CURLOPT_FORBID_REUSE, 0L);

    const auto perform = [this, &result, &errorBuffer]() {
        const CURLMcode addResult = curl_multi_add_handle(m_multi, m_curl);
        if (addResult != CURLM_OK) {
            result.code = CURLE_FAILED_INIT;
            result.error = curl_multi_strerror(addResult);
            return;
        }

        int running = 0;
        CURLMcode multiResult = curl_multi_perform(m_multi, &running);
        while (multiResult == CURLM_OK && running > 0 && !m_cancelled.load(std::memory_order_relaxed)) {
            int descriptorCount = 0;
            multiResult = curl_multi_poll(m_multi, nullptr, 0, 100, &descriptorCount);
            if (multiResult == CURLM_OK) {
                multiResult = curl_multi_perform(m_multi, &running);
            }
        }

        if (m_cancelled.load(std::memory_order_relaxed)) {
            result.code = CURLE_ABORTED_BY_CALLBACK;
        } else if (multiResult != CURLM_OK) {
            result.code = CURLE_RECV_ERROR;
            result.error = curl_multi_strerror(multiResult);
        } else {
            result.code = CURLE_RECV_ERROR;
            int messageCount = 0;
            while (CURLMsg* message = curl_multi_info_read(m_multi, &messageCount)) {
                if (message->msg == CURLMSG_DONE && message->easy_handle == m_curl) {
                    result.code = message->data.result;
                    break;
                }
            }
        }

        curl_easy_getinfo(m_curl, CURLINFO_TOTAL_TIME_T, &result.elapsedUs);
        curl_multi_remove_handle(m_multi, m_curl);
        if (result.error.isEmpty()) {
            result.error = errorBuffer[0] != '\0' ? QByteArray(errorBuffer) : QByteArray(curl_easy_strerror(result.code));
        }
    };

    perform();

    if (!m_cancelled.load(std::memory_order_relaxed) && retryableHttp2Error(result.code)) {
        const curl_off_t firstAttemptUs = result.elapsedUs;
        result.payload.clear();
        result.error.clear();
        errorBuffer[0] = '\0';
        curl_easy_setopt(m_curl, CURLOPT_FRESH_CONNECT, 1L);
        perform();
        result.elapsedUs += firstAttemptUs;
        curl_easy_setopt(m_curl, CURLOPT_FRESH_CONNECT, 0L);
    }

    curl_easy_getinfo(m_curl, CURLINFO_RESPONSE_CODE, &result.statusCode);
    curl_easy_getinfo(m_curl, CURLINFO_HTTP_VERSION, &result.httpVersion);
    return result;
}

void DohResolver::finishQuery()
{
    const CurlResult result = m_watcher.result();
    const QUrl url = endpoint();
    m_lastQueryTransport = transportName(result.httpVersion);

    bool success = false;
    if (m_cancelled.load(std::memory_order_relaxed)) {
        m_lastError = QStringLiteral("cancelled");
    } else if (result.code != CURLE_OK) {
        m_lastError = QStringLiteral("%1 (%2)%3")
            .arg(QString::fromLocal8Bit(result.error))
            .arg(static_cast<int>(result.code))
            .arg(resolutionHint(url.host()));
    } else if (result.statusCode < 200 || result.statusCode >= 300) {
        m_lastError = QStringLiteral("HTTP %1 from %2").arg(result.statusCode).arg(url.toString());
    } else if (!DnsPacket::isValidResponse(result.payload, m_transactionId, m_domain, 1)) {
        m_lastError = QStringLiteral("invalid DNS message response from %1: %2 bytes").arg(url.toString()).arg(result.payload.size());
    } else {
        m_lastAuthenticatedDataBit = DnsPacket::authenticatedDataBit(result.payload);
        success = true;
    }

    QueryCallback callback = std::move(m_callback);
    if (callback) {
        callback(success ? result.elapsedUs / 1000.0 : 0.0, success);
    }
}
