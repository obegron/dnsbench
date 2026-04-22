#include "benchmark/BenchmarkController.h"

#include "benchmark/DohResolver.h"
#include "benchmark/DotResolver.h"
#include "benchmark/UdpResolver.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <QMetaObject>
#include <QPointer>
#include <QRandomGenerator>
#include <QRunnable>
#include <QThread>

#include <algorithm>
#include <memory>
#include <random>

namespace {

constexpr int fullQueryTimeoutMs = 5000;
constexpr int udpWarmupTimeoutMs = 1000;
constexpr int encryptedWarmupTimeoutMs = 8000;
constexpr int warmupCount = 10;
constexpr int warmupSuccessThreshold = 3;

int warmupTimeoutForProtocol(ResolverProtocol protocol)
{
    switch (protocol) {
    case ResolverProtocol::DoH:
    case ResolverProtocol::DoT:
        return encryptedWarmupTimeoutMs;
    case ResolverProtocol::IPv4:
    case ResolverProtocol::IPv6:
        return udpWarmupTimeoutMs;
    }
    return udpWarmupTimeoutMs;
}

std::unique_ptr<BaseResolver> createResolverForThread(const ResolverEntry& entry, int timeoutMs)
{
    switch (entry.protocol) {
    case ResolverProtocol::IPv4:
    case ResolverProtocol::IPv6:
        return std::make_unique<UdpResolver>(entry, timeoutMs);
    case ResolverProtocol::DoH:
        return std::make_unique<DohResolver>(entry, timeoutMs);
    case ResolverProtocol::DoT:
        return std::make_unique<DotResolver>(entry, timeoutMs);
    }
    return std::make_unique<UdpResolver>(entry, timeoutMs);
}

}

class ResolverBenchmarkTask final : public QRunnable {
public:
    ResolverBenchmarkTask(
        QPointer<BenchmarkController> controller,
        ResolverEntry entry,
        int sampleCount,
        int interQueryDelayMs,
        QStringList domains,
        bool verboseLogging,
        std::shared_ptr<std::atomic_bool> cancelled)
        : m_controller(std::move(controller))
        , m_entry(std::move(entry))
        , m_sampleCount(sampleCount)
        , m_interQueryDelayMs(std::max(0, interQueryDelayMs))
        , m_domains(std::move(domains))
        , m_verboseLogging(verboseLogging)
        , m_cancelled(std::move(cancelled))
    {
        setAutoDelete(true);
    }

    void run() override
    {
        if (isCancelled()) {
            postComplete();
            return;
        }

        postStatus(ResolverStatus::Running);
        postLog(QStringLiteral("Warming up %1 (%2).").arg(m_entry.effectiveName(), protocolToString(m_entry.protocol)));

        auto resolver = createResolverForThread(m_entry, warmupTimeoutForProtocol(m_entry.protocol));
        int successes = 0;
        QString firstWarmupError;
        for (int i = 0; i < warmupCount && !isCancelled(); ++i) {
            qint64 rttMs = 0;
            QString error;
            if (queryBlocking(resolver.get(), domainForSample(i), &rttMs, &error)) {
                ++successes;
            } else if (firstWarmupError.isEmpty()) {
                firstWarmupError = error;
            }
        }

        if (isCancelled()) {
            postComplete();
            return;
        }

        if (successes < warmupSuccessThreshold) {
            const Statistics stats = Statistics::fromSamples({}, m_sampleCount);
            postStatus(ResolverStatus::Sidelined);
            postResolverFinished(stats, ResolverStatus::Sidelined, false, {});
            QString message = QStringLiteral("Sidelined %1: %2/%3 warm-up responses.")
                    .arg(m_entry.effectiveName())
                    .arg(successes)
                    .arg(warmupCount);
            if (!firstWarmupError.isEmpty()) {
                message += QStringLiteral(" Last error: %1.").arg(firstWarmupError);
            }
            postLog(message);
            postProgress(m_sampleCount);
            postComplete();
            return;
        }

        postLog(QStringLiteral("Warm-up passed for %1: %2/%3 responses.")
                .arg(m_entry.effectiveName())
                .arg(successes)
                .arg(warmupCount));

        QVector<qint64> samples;
        samples.reserve(m_sampleCount);
        QVector<ResolverSamplePoint> samplePoints;
        samplePoints.reserve(m_sampleCount);
        bool dnssecAuthenticatedDataSeen = false;
        resolver->setTimeoutMs(fullQueryTimeoutMs);

        for (int i = 0; i < m_sampleCount && !isCancelled(); ++i) {
            const QString domain = domainForSample(i);
            postVerboseLog(QStringLiteral("Query %1 via %2.").arg(domain, m_entry.effectiveName()));

            qint64 rttMs = 0;
            QString error;
            const bool success = queryBlocking(resolver.get(), domain, &rttMs, &error);
            if (success) {
                samples.push_back(rttMs);
                samplePoints.push_back({i, rttMs, true});
                dnssecAuthenticatedDataSeen = dnssecAuthenticatedDataSeen || resolver->lastAuthenticatedDataBit();
                postVerboseLog(QStringLiteral("Response %1 via %2 in %3 ms.")
                        .arg(domain, m_entry.effectiveName())
                        .arg(rttMs));
            } else {
                samplePoints.push_back({i, 0, false});
                postVerboseLog(error.isEmpty()
                    ? QStringLiteral("Timeout/failure for %1 via %2.").arg(domain, m_entry.effectiveName())
                    : QStringLiteral("Failure for %1 via %2: %3.").arg(domain, m_entry.effectiveName(), error));
            }
            postProgress(1);
            if (i + 1 < m_sampleCount) {
                sleepBetweenQueries();
            }
        }

        if (!isCancelled()) {
            const Statistics stats = Statistics::fromSamples(samples, m_sampleCount);
            postResolverFinished(stats, ResolverStatus::Finished, dnssecAuthenticatedDataSeen, samplePoints);
            postLog(QStringLiteral("Finished %1: median %2 ms, loss %3%.")
                    .arg(m_entry.effectiveName())
                    .arg(stats.medianMs, 0, 'f', 1)
                    .arg(stats.lossPercent, 0, 'f', 1));
        }

        postComplete();
    }

private:
    QPointer<BenchmarkController> m_controller;
    ResolverEntry m_entry;
    int m_sampleCount = 0;
    int m_interQueryDelayMs = 50;
    QStringList m_domains;
    bool m_verboseLogging = false;
    std::shared_ptr<std::atomic_bool> m_cancelled;

    bool isCancelled() const
    {
        return !m_cancelled || m_cancelled->load(std::memory_order_relaxed);
    }

    QString domainForSample(int sampleIndex) const
    {
        return m_domains.at(sampleIndex % m_domains.size());
    }

    bool queryBlocking(BaseResolver* resolver, const QString& domain, qint64* rttMs, QString* errorString)
    {
        if (isCancelled()) {
            return false;
        }

        QEventLoop loop;
        bool done = false;
        bool success = false;
        qint64 rtt = 0;

        resolver->query(domain, [&](qint64 measuredRttMs, bool measuredSuccess) {
            rtt = measuredRttMs;
            success = measuredSuccess;
            done = true;
            loop.quit();
        });

        if (!done) {
            loop.exec();
        }

        if (rttMs) {
            *rttMs = rtt;
        }
        if (errorString) {
            *errorString = success ? QString() : resolver->lastErrorString();
        }
        return !isCancelled() && success;
    }

    void sleepBetweenQueries()
    {
        int remainingMs = m_interQueryDelayMs;
        while (remainingMs > 0 && !isCancelled()) {
            const int sliceMs = std::min(remainingMs, 50);
            QThread::msleep(static_cast<unsigned long>(sliceMs));
            remainingMs -= sliceMs;
        }
    }

    void postStatus(ResolverStatus status)
    {
        post([id = m_entry.id, status](BenchmarkController* controller) {
            if (controller->m_running) {
                emit controller->resolverStatusChanged(id, status);
            }
        });
    }

    void postLog(QString line)
    {
        post([line = std::move(line)](BenchmarkController* controller) {
            if (controller->m_running) {
                emit controller->logLine(line);
            }
        });
    }

    void postVerboseLog(QString line)
    {
        if (m_verboseLogging) {
            postLog(std::move(line));
        }
    }

    void postProgress(int completedDelta)
    {
        post([completedDelta](BenchmarkController* controller) {
            controller->handleTaskProgress(completedDelta);
        });
    }

    void postResolverFinished(Statistics stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, QVector<ResolverSamplePoint> samples)
    {
        post([id = m_entry.id, stats, status, dnssecAuthenticatedDataSeen, samples = std::move(samples)](BenchmarkController* controller) {
            if (controller->m_running) {
                emit controller->resolverFinished(id, stats, status, dnssecAuthenticatedDataSeen, samples);
            }
        });
    }

    void postComplete()
    {
        post([](BenchmarkController* controller) {
            controller->handleTaskComplete();
        });
    }

    template <typename Function>
    void post(Function&& function)
    {
        const QPointer<BenchmarkController> controller = m_controller;
        const std::shared_ptr<std::atomic_bool> cancelled = m_cancelled;
        QMetaObject::invokeMethod(QCoreApplication::instance(), [controller, cancelled, fn = std::forward<Function>(function)]() mutable {
            if (!controller || !cancelled || cancelled->load(std::memory_order_relaxed)) {
                return;
            }
            fn(controller.data());
        }, Qt::QueuedConnection);
    }
};

BenchmarkController::BenchmarkController(QObject* parent)
    : QObject(parent)
{
    m_threadPool.setMaxThreadCount(20);
}

void BenchmarkController::start(const QList<ResolverEntry>& resolvers, int sampleCount, int interQueryDelayMs, QStringList domains)
{
    stop();

    m_resolvers = resolvers;
    m_sampleCount = std::max(1, sampleCount);
    m_interQueryDelayMs = std::max(0, interQueryDelayMs);
    m_domains = std::move(domains);
    if (m_domains.isEmpty()) {
        m_domains = {QStringLiteral("example.com"), QStringLiteral("qt.io"), QStringLiteral("cloudflare.com")};
    }

    std::shuffle(m_domains.begin(), m_domains.end(), std::mt19937(QRandomGenerator::global()->generate()));

    m_completed = 0;
    m_finishedResolvers = 0;
    m_lastProgressEmitMs = 0;
    m_total = m_resolvers.size() * m_sampleCount;
    m_running = true;
    m_cancelled = std::make_shared<std::atomic_bool>(false);
    m_elapsed.start();

    emit progressUpdated(0, m_total, 0);
    emit logLine(QStringLiteral("Running up to %1 resolver(s) in parallel.").arg(m_threadPool.maxThreadCount()));
    emit logLine(QStringLiteral("Inter-query delay: %1 ms.").arg(m_interQueryDelayMs));

    if (m_resolvers.isEmpty()) {
        finishAll();
        return;
    }

    for (const ResolverEntry& entry : std::as_const(m_resolvers)) {
        m_threadPool.start(new ResolverBenchmarkTask(QPointer<BenchmarkController>(this), entry, m_sampleCount, m_interQueryDelayMs, m_domains, m_verboseLogging, m_cancelled));
    }
}

void BenchmarkController::stop()
{
    if (!m_running) {
        return;
    }

    m_running = false;
    if (m_cancelled) {
        m_cancelled->store(true, std::memory_order_relaxed);
    }
    m_threadPool.clear();
    emit logLine(QStringLiteral("Benchmark stopped."));
    emit benchmarkFinished();
}

bool BenchmarkController::isRunning() const
{
    return m_running;
}

void BenchmarkController::setMaxConcurrentResolvers(int maxConcurrentResolvers)
{
    m_threadPool.setMaxThreadCount(std::max(1, maxConcurrentResolvers));
}

void BenchmarkController::setVerboseLogging(bool verboseLogging)
{
    m_verboseLogging = verboseLogging;
}

void BenchmarkController::handleTaskProgress(int completedDelta)
{
    if (!m_running) {
        return;
    }

    m_completed = std::min(m_total, m_completed + completedDelta);
    const qint64 elapsedMs = m_elapsed.elapsed();
    if (m_completed >= m_total || elapsedMs - m_lastProgressEmitMs >= 100) {
        m_lastProgressEmitMs = elapsedMs;
        emit progressUpdated(m_completed, m_total, elapsedMs);
    }
}

void BenchmarkController::handleTaskComplete()
{
    if (!m_running) {
        return;
    }

    ++m_finishedResolvers;
    if (m_finishedResolvers >= m_resolvers.size()) {
        finishAll();
    }
}

void BenchmarkController::finishAll()
{
    if (!m_running) {
        return;
    }

    m_running = false;
    if (m_cancelled) {
        m_cancelled->store(true, std::memory_order_relaxed);
    }
    emit progressUpdated(m_completed, m_total, m_elapsed.elapsed());
    emit logLine(QStringLiteral("Benchmark complete."));
    emit benchmarkFinished();
}
