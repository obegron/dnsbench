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
        QStringList domains,
        std::shared_ptr<std::atomic_bool> cancelled)
        : m_controller(std::move(controller))
        , m_entry(std::move(entry))
        , m_sampleCount(sampleCount)
        , m_domains(std::move(domains))
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
        for (int i = 0; i < warmupCount && !isCancelled(); ++i) {
            qint64 rttMs = 0;
            if (queryBlocking(resolver.get(), domainForSample(i), &rttMs)) {
                ++successes;
            }
        }

        if (isCancelled()) {
            postComplete();
            return;
        }

        if (successes < warmupSuccessThreshold) {
            const Statistics stats = Statistics::fromSamples({}, m_sampleCount);
            postStatus(ResolverStatus::Sidelined);
            postResolverFinished(stats, ResolverStatus::Sidelined);
            postLog(QStringLiteral("Sidelined %1: %2/%3 warm-up responses.")
                    .arg(m_entry.effectiveName())
                    .arg(successes)
                    .arg(warmupCount));
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
        resolver->setTimeoutMs(fullQueryTimeoutMs);

        for (int i = 0; i < m_sampleCount && !isCancelled(); ++i) {
            const QString domain = domainForSample(i);
            postLog(QStringLiteral("Query %1 via %2.").arg(domain, m_entry.effectiveName()));

            qint64 rttMs = 0;
            const bool success = queryBlocking(resolver.get(), domain, &rttMs);
            if (success) {
                samples.push_back(rttMs);
                postLog(QStringLiteral("Response %1 via %2 in %3 ms.")
                        .arg(domain, m_entry.effectiveName())
                        .arg(rttMs));
            } else {
                postLog(QStringLiteral("Timeout/failure for %1 via %2.").arg(domain, m_entry.effectiveName()));
            }
            postProgress(1);
        }

        if (!isCancelled()) {
            const Statistics stats = Statistics::fromSamples(samples, m_sampleCount);
            postResolverFinished(stats, ResolverStatus::Finished);
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
    QStringList m_domains;
    std::shared_ptr<std::atomic_bool> m_cancelled;

    bool isCancelled() const
    {
        return !m_cancelled || m_cancelled->load(std::memory_order_relaxed);
    }

    QString domainForSample(int sampleIndex) const
    {
        return m_domains.at(sampleIndex % m_domains.size());
    }

    bool queryBlocking(BaseResolver* resolver, const QString& domain, qint64* rttMs)
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
        return !isCancelled() && success;
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

    void postProgress(int completedDelta)
    {
        post([completedDelta](BenchmarkController* controller) {
            controller->handleTaskProgress(completedDelta);
        });
    }

    void postResolverFinished(Statistics stats, ResolverStatus status)
    {
        post([id = m_entry.id, stats, status](BenchmarkController* controller) {
            if (controller->m_running) {
                emit controller->resolverFinished(id, stats, status);
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

void BenchmarkController::start(const QList<ResolverEntry>& resolvers, int sampleCount, QStringList domains)
{
    stop();

    m_resolvers = resolvers;
    m_sampleCount = std::max(1, sampleCount);
    m_domains = std::move(domains);
    if (m_domains.isEmpty()) {
        m_domains = {QStringLiteral("example.com"), QStringLiteral("qt.io"), QStringLiteral("cloudflare.com")};
    }

    std::shuffle(m_domains.begin(), m_domains.end(), std::mt19937(QRandomGenerator::global()->generate()));

    m_completed = 0;
    m_finishedResolvers = 0;
    m_total = m_resolvers.size() * m_sampleCount;
    m_running = true;
    m_cancelled = std::make_shared<std::atomic_bool>(false);
    m_elapsed.start();

    emit progressUpdated(0, m_total, 0);
    emit logLine(QStringLiteral("Running up to %1 resolver(s) in parallel.").arg(m_threadPool.maxThreadCount()));

    if (m_resolvers.isEmpty()) {
        finishAll();
        return;
    }

    for (const ResolverEntry& entry : std::as_const(m_resolvers)) {
        m_threadPool.start(new ResolverBenchmarkTask(QPointer<BenchmarkController>(this), entry, m_sampleCount, m_domains, m_cancelled));
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

void BenchmarkController::handleTaskProgress(int completedDelta)
{
    if (!m_running) {
        return;
    }

    m_completed = std::min(m_total, m_completed + completedDelta);
    emit progressUpdated(m_completed, m_total, m_elapsed.elapsed());
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
    emit logLine(QStringLiteral("Benchmark complete."));
    emit benchmarkFinished();
}
