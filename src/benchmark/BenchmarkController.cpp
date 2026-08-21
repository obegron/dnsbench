#include "benchmark/BenchmarkController.h"

#include "benchmark/DohResolver.h"
#include "benchmark/DotResolver.h"
#include "benchmark/UdpResolver.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QMetaObject>
#include <QPointer>
#include <QRandomGenerator>
#include <QRunnable>
#include <QThread>

#include <algorithm>
#include <memory>
#include <random>
#include <vector>

namespace {

constexpr int fullQueryTimeoutMs = 5000;
constexpr int encryptedWarmupTimeoutMs = 8000;
constexpr int warmupCount = 10;
constexpr int warmupSuccessThreshold = 3;
constexpr int cachePrimeNoResponseLimit = 3;
constexpr int earlyNoResponseLimit = 3;
constexpr int stopWaitMs = 6000;
constexpr int cancellationPollMs = 25;
constexpr int partialResultSampleBatch = 5;
bool requiresWarmup(ResolverProtocol protocol)
{
    switch (protocol) {
    case ResolverProtocol::DoH:
    case ResolverProtocol::DoT:
        return true;
    case ResolverProtocol::IPv4:
    case ResolverProtocol::IPv6:
        return false;
    }
    return false;
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

int resolverDomainOffset(const ResolverEntry& entry, int resolverIndex, int domainCount)
{
    if (domainCount <= 1) {
        return 0;
    }
    const uint hash = qHash(entry.id.isEmpty() ? entry.effectiveName() : entry.id);
    return static_cast<int>((hash + static_cast<uint>(resolverIndex)) % static_cast<uint>(domainCount));
}

int warmupQueryCount(const QList<ResolverEntry>& resolvers)
{
    int count = 0;
    for (const ResolverEntry& resolver : resolvers) {
        if (requiresWarmup(resolver.protocol)) {
            count += warmupCount;
        }
    }
    return count;
}

}

class BenchmarkRunnerTask final : public QRunnable {
public:
    BenchmarkRunnerTask(
        QPointer<BenchmarkController> controller,
        QList<ResolverEntry> entries,
        int sampleCount,
        int interQueryDelayMs,
        QStringList domains,
        bool primeCache,
        bool includeUncached,
        bool verboseLogging,
        bool summaryLogging,
        std::shared_ptr<std::atomic_bool> cancelled)
        : m_controller(std::move(controller))
        , m_entries(std::move(entries))
        , m_sampleCount(sampleCount)
        , m_interQueryDelayMs(std::max(0, interQueryDelayMs))
        , m_domains(std::move(domains))
        , m_primeCache(primeCache)
        , m_includeUncached(includeUncached)
        , m_verboseLogging(verboseLogging)
        , m_summaryLogging(summaryLogging)
        , m_cancelled(std::move(cancelled))
    {
        setAutoDelete(true);
    }

    void run() override
    {
        m_progressPostTimer.start();
        if (isCancelled()) {
            return;
        }

        std::vector<ResolverState> states;
        states.reserve(m_entries.size());
        for (int i = 0; i < m_entries.size(); ++i) {
            const ResolverEntry& entry = m_entries.at(i);
            ResolverState state;
            state.entry = entry;
            state.resolver = createResolverForThread(entry, fullQueryTimeoutMs);
            state.domainOffset = resolverDomainOffset(entry, i, m_domains.size());
            state.samplePoints.reserve(m_sampleCount);
            state.rtts.reserve(m_sampleCount);
            states.push_back(std::move(state));
            postStatus(entry.id, ResolverStatus::Running);
        }

        warmResolvers(&states);
        primeResolvers(&states);
        measureResolvers(&states);
        measureUncachedResolvers(&states);
        if (isCancelled()) {
            return;
        }

        for (const ResolverState& state : states) {
            postResolverFinished(state);
        }
        postProgress(0, true);
        postComplete();
    }

private:
    struct ResolverState {
        ResolverEntry entry;
        std::unique_ptr<BaseResolver> resolver;
        int domainOffset = 0;
        QVector<double> rtts;
        QVector<ResolverSamplePoint> samplePoints;
        QVector<double> uncachedRtts;
        QVector<ResolverSamplePoint> uncachedSamplePoints;
        bool dnssecAuthenticatedDataSeen = false;
        bool stoppedForNoResponse = false;
        bool sidelined = false;
        int primeSuccesses = 0;
        int primeFailuresBeforeFirstSuccess = 0;
        int lastPostedSampleCount = 0;
    };

    QPointer<BenchmarkController> m_controller;
    QList<ResolverEntry> m_entries;
    int m_sampleCount = 0;
    int m_interQueryDelayMs = 50;
    QStringList m_domains;
    QString m_uncachedRunNonce = QString::number(QRandomGenerator::global()->generate64(), 36);
    bool m_primeCache = true;
    bool m_includeUncached = false;
    bool m_verboseLogging = false;
    bool m_summaryLogging = true;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    QElapsedTimer m_progressPostTimer;
    int m_pendingProgressDelta = 0;

    void warmResolvers(std::vector<ResolverState>* states)
    {
        for (ResolverState& state : *states) {
            if (isCancelled()) {
                return;
            }
            if (!requiresWarmup(state.entry.protocol)) {
                continue;
            }

            postSummaryLog(QStringLiteral("Warming up %1 (%2).")
                .arg(state.entry.effectiveName(), protocolToString(state.entry.protocol)));
            state.resolver = createResolverForThread(state.entry, encryptedWarmupTimeoutMs);

            int successes = 0;
            QString firstWarmupError;
            for (int i = 0; i < warmupCount && !isCancelled(); ++i) {
                double rttMs = 0.0;
                QString error;
                if (queryBlocking(state.resolver.get(), domainForSample(state, i), &rttMs, &error)) {
                    ++successes;
                } else if (firstWarmupError.isEmpty()) {
                    firstWarmupError = error;
                }
                postProgress(1);
                sleepBetweenQueries();
            }

            if (isCancelled()) {
                return;
            }
            if (successes < warmupSuccessThreshold) {
                state.sidelined = true;
                postStatus(state.entry.id, ResolverStatus::Sidelined);
                QString message = QStringLiteral("Sidelined %1: %2/%3 warm-up responses.")
                    .arg(state.entry.effectiveName())
                    .arg(successes)
                    .arg(warmupCount);
                if (!firstWarmupError.isEmpty()) {
                    message += QStringLiteral(" Last error: %1.").arg(firstWarmupError);
                }
                postSummaryLog(message);
                postProgress(primeQueryCount() + measuredQueryCount(), true);
            } else {
                state.resolver->setTimeoutMs(fullQueryTimeoutMs);
                postSummaryLog(QStringLiteral("Warm-up passed for %1: %2/%3 responses.")
                    .arg(state.entry.effectiveName())
                    .arg(successes)
                    .arg(warmupCount));
            }
        }
    }

    void primeResolvers(std::vector<ResolverState>* states)
    {
        if (!m_primeCache) {
            return;
        }

        const int primeCount = std::min(m_sampleCount, static_cast<int>(m_domains.size()));
        for (int sample = 0; sample < primeCount && !isCancelled(); ++sample) {
            for (ResolverState& state : *states) {
                if (isCancelled()) {
                    return;
                }
                if (state.sidelined) {
                    continue;
                }
                double ignoredRttMs = 0.0;
                QString error;
                const bool success = queryBlocking(state.resolver.get(), domainForSample(state, sample), &ignoredRttMs, &error);
                if (success) {
                    ++state.primeSuccesses;
                } else if (state.primeSuccesses == 0 && ++state.primeFailuresBeforeFirstSuccess >= cachePrimeNoResponseLimit) {
                    state.sidelined = true;
                    postStatus(state.entry.id, ResolverStatus::Sidelined);
                    postSummaryLog(QStringLiteral("Sidelined %1: no responses during cache warm-up. Last error: %2.")
                        .arg(state.entry.effectiveName(), error));
                    const int skippedPrimeQueries = primeCount - sample - 1;
                    postProgress(skippedPrimeQueries + measuredQueryCount(), true);
                }
                postProgress(1);
                sleepBetweenQueries();
            }
        }
    }

    void measureResolvers(std::vector<ResolverState>* states)
    {
        for (ResolverState& state : *states) {
            if (!state.sidelined) {
                state.resolver->setTimeoutMs(fullQueryTimeoutMs);
            }
        }

        for (int sample = 0; sample < m_sampleCount && !isCancelled(); ++sample) {
            for (ResolverState& state : *states) {
                if (isCancelled()) {
                    return;
                }
                if (state.sidelined) {
                    continue;
                }

                const QString domain = domainForSample(state, sample);
                postVerboseLog(QStringLiteral("Query %1 via %2.").arg(domain, state.entry.effectiveName()));

                double rttMs = 0.0;
                QString error;
                const bool success = queryBlocking(state.resolver.get(), domain, &rttMs, &error);
                if (success) {
                    state.rtts.push_back(rttMs);
                    state.samplePoints.push_back({sample, rttMs, true, {}});
                    state.dnssecAuthenticatedDataSeen = state.dnssecAuthenticatedDataSeen || state.resolver->lastAuthenticatedDataBit();
                    const QString transport = state.resolver->lastQueryTransport();
                    postVerboseLog(QStringLiteral("Response %1 via %2 in %3 ms%4.")
                        .arg(domain, state.entry.effectiveName())
                        .arg(rttMs, 0, 'f', 3)
                        .arg(transport.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(transport)));
                } else {
                    state.samplePoints.push_back({sample, 0, false, error});
                    postVerboseLog(error.isEmpty()
                        ? QStringLiteral("Timeout/failure for %1 via %2.").arg(domain, state.entry.effectiveName())
                        : QStringLiteral("Failure for %1 via %2: %3.").arg(domain, state.entry.effectiveName(), error));
                    if (state.rtts.isEmpty() && state.samplePoints.size() >= earlyNoResponseLimit) {
                        state.stoppedForNoResponse = true;
                        state.sidelined = true;
                        postStatus(state.entry.id, ResolverStatus::Sidelined);
                        const int samplesToMarkComplete = (m_sampleCount - sample - 1) + (m_includeUncached ? m_sampleCount : 0);
                        if (samplesToMarkComplete > 0) {
                            postProgress(samplesToMarkComplete, true);
                        }
                        postSummaryLog(QStringLiteral("Sidelined %1: no responses in the first %2 full-timeout queries.")
                            .arg(state.entry.effectiveName())
                            .arg(earlyNoResponseLimit));
                    }
                }
                postProgress(1);
                postPartialResultIfNeeded(&state);
                sleepBetweenQueries();
            }
        }
    }

    void measureUncachedResolvers(std::vector<ResolverState>* states)
    {
        if (!m_includeUncached) {
            return;
        }

        postSummaryLog(QStringLiteral("Starting uncached pass using random labels under the benchmark site list; cache warm-up is skipped for this pass."));
        for (int sample = 0; sample < m_sampleCount && !isCancelled(); ++sample) {
            for (ResolverState& state : *states) {
                if (isCancelled()) {
                    return;
                }
                if (state.sidelined) {
                    continue;
                }

                const QString domain = uncachedDomainForSample(state, sample);
                postVerboseLog(QStringLiteral("Uncached query %1 via %2.").arg(domain, state.entry.effectiveName()));

                double rttMs = 0.0;
                QString error;
                const bool success = queryBlocking(state.resolver.get(), domain, &rttMs, &error);
                if (success) {
                    state.uncachedRtts.push_back(rttMs);
                    state.uncachedSamplePoints.push_back({sample, rttMs, true, {}, 1});
                    state.dnssecAuthenticatedDataSeen = state.dnssecAuthenticatedDataSeen || state.resolver->lastAuthenticatedDataBit();
                    const QString transport = state.resolver->lastQueryTransport();
                    postVerboseLog(QStringLiteral("Uncached response %1 via %2 in %3 ms%4.")
                        .arg(domain, state.entry.effectiveName())
                        .arg(rttMs, 0, 'f', 3)
                        .arg(transport.isEmpty() ? QString() : QStringLiteral(" (%1)").arg(transport)));
                } else {
                    state.uncachedSamplePoints.push_back({sample, 0, false, error, 1});
                    postVerboseLog(error.isEmpty()
                        ? QStringLiteral("Uncached timeout/failure for %1 via %2.").arg(domain, state.entry.effectiveName())
                        : QStringLiteral("Uncached failure for %1 via %2: %3.").arg(domain, state.entry.effectiveName(), error));
                }
                postProgress(1);
                sleepBetweenQueries();
            }
        }
    }

    bool isCancelled() const
    {
        return !m_cancelled || m_cancelled->load(std::memory_order_relaxed);
    }

    QString domainForSample(const ResolverState& state, int sampleIndex) const
    {
        return m_domains.at((sampleIndex + state.domainOffset) % m_domains.size());
    }

    QString uncachedDomainForSample(const ResolverState& state, int sampleIndex) const
    {
        const QString baseDomain = domainForSample(state, sampleIndex);
        return QStringLiteral("dnsbench-%1-%2-%3.%4")
            .arg(m_uncachedRunNonce)
            .arg(QString::number(QRandomGenerator::global()->generate64(), 36))
            .arg(sampleIndex)
            .arg(baseDomain);
    }

    int primeQueryCount() const
    {
        return m_primeCache ? std::min(m_sampleCount, static_cast<int>(m_domains.size())) : 0;
    }

    int measuredQueryCount() const
    {
        return m_sampleCount * (m_includeUncached ? 2 : 1);
    }

    bool queryBlocking(BaseResolver* resolver, const QString& domain, double* rttMs, QString* errorString)
    {
        if (isCancelled()) {
            return false;
        }

        QEventLoop loop;
        QTimer cancellationTimer;
        bool done = false;
        bool success = false;
        double rtt = 0.0;

        cancellationTimer.setInterval(cancellationPollMs);
        QObject::connect(&cancellationTimer, &QTimer::timeout, &loop, [&]() {
            if (!done && isCancelled()) {
                done = true;
                success = false;
                resolver->cancel();
                loop.quit();
            }
        });

        resolver->query(domain, [&](double measuredRttMs, bool measuredSuccess) {
            rtt = measuredRttMs;
            success = measuredSuccess;
            done = true;
            loop.quit();
        });

        if (!done) {
            cancellationTimer.start();
            loop.exec();
        }
        cancellationTimer.stop();

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

    void postStatus(const QString& id, ResolverStatus status)
    {
        post([id, status](BenchmarkController* controller) {
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

    void postSummaryLog(QString line)
    {
        if (m_summaryLogging || m_verboseLogging) {
            postLog(std::move(line));
        }
    }

    void postProgress(int completedDelta, bool force = false)
    {
        m_pendingProgressDelta += completedDelta;
        if (m_pendingProgressDelta <= 0) {
            return;
        }
        if (!force && m_progressPostTimer.isValid() && m_progressPostTimer.elapsed() < 100) {
            return;
        }

        const int deltaToPost = m_pendingProgressDelta;
        m_pendingProgressDelta = 0;
        m_progressPostTimer.restart();
        post([deltaToPost](BenchmarkController* controller) {
            controller->handleTaskProgress(deltaToPost);
        });
    }

    void postResolverFinished(const ResolverState& state)
    {
        const ResolverStatus status = state.stoppedForNoResponse || state.sidelined ? ResolverStatus::Sidelined : ResolverStatus::Finished;
        if (status == ResolverStatus::Finished) {
            const Statistics stats = Statistics::fromSamples(state.rtts, m_sampleCount);
            const Statistics uncachedStats = m_includeUncached
                ? Statistics::fromSamples(state.uncachedRtts, m_sampleCount)
                : Statistics();
            QString message = QStringLiteral("Finished %1: cached median %2 ms, loss %3%.")
                .arg(state.entry.effectiveName())
                .arg(stats.medianMs, 0, 'f', 1)
                .arg(stats.lossPercent, 0, 'f', 1);
            if (m_includeUncached) {
                message += QStringLiteral(" Uncached median %1 ms, loss %2%.")
                    .arg(uncachedStats.medianMs, 0, 'f', 1)
                    .arg(uncachedStats.lossPercent, 0, 'f', 1);
            }
            postSummaryLog(message);
        }
        postResolverUpdate(state, status, m_sampleCount);
    }

    void postPartialResultIfNeeded(ResolverState* state)
    {
        const int sampleCount = state->samplePoints.size();
        if (sampleCount <= 0 || sampleCount == state->lastPostedSampleCount) {
            return;
        }
        if (sampleCount == 1 || sampleCount % partialResultSampleBatch == 0 || state->sidelined) {
            state->lastPostedSampleCount = sampleCount;
            const int expectedTotal = state->sidelined ? m_sampleCount : sampleCount;
            postResolverUpdate(*state, state->sidelined ? ResolverStatus::Sidelined : ResolverStatus::Running, expectedTotal);
        }
    }

    void postResolverUpdate(const ResolverState& state, ResolverStatus status, int expectedTotal)
    {
        const Statistics stats = Statistics::fromSamples(state.rtts, expectedTotal);
        const Statistics uncachedStats = m_includeUncached
            ? Statistics::fromSamples(state.uncachedRtts, state.uncachedSamplePoints.isEmpty() ? 0 : expectedTotal)
            : Statistics();
        post([id = state.entry.id, stats, status, dnssec = state.dnssecAuthenticatedDataSeen, samples = state.samplePoints, uncachedStats, uncachedSamples = state.uncachedSamplePoints](BenchmarkController* controller) {
            if (controller->m_running) {
                emit controller->resolverFinished(id, stats, status, dnssec, samples, uncachedStats, uncachedSamples);
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
    m_threadPool.setMaxThreadCount(1);
    m_threadPool.setExpiryTimeout(0);
}

BenchmarkController::~BenchmarkController()
{
    stop();
}

void BenchmarkController::start(const QList<ResolverEntry>& resolvers, int sampleCount, int interQueryDelayMs, QStringList domains, bool primeCache, bool includeUncached)
{
    stop();

    m_resolvers = resolvers;
    m_sampleCount = std::max(1, sampleCount);
    m_interQueryDelayMs = std::max(0, interQueryDelayMs);
    m_primeCache = primeCache;
    m_domains = std::move(domains);
    if (m_domains.isEmpty()) {
        m_domains = {QStringLiteral("example.com"), QStringLiteral("qt.io"), QStringLiteral("cloudflare.com")};
    }

    std::shuffle(m_domains.begin(), m_domains.end(), std::mt19937(QRandomGenerator::global()->generate()));
    std::shuffle(m_resolvers.begin(), m_resolvers.end(), std::mt19937(QRandomGenerator::global()->generate()));

    m_completed = 0;
    m_finishedResolvers = 0;
    m_lastProgressEmitMs = 0;
    const int measuredQueryCount = m_resolvers.size() * m_sampleCount * (includeUncached ? 2 : 1);
    const int primeQueryTotal = m_primeCache
        ? m_resolvers.size() * std::min(m_sampleCount, static_cast<int>(m_domains.size()))
        : 0;
    m_total = measuredQueryCount + primeQueryTotal + warmupQueryCount(m_resolvers);
    m_running = true;
    m_cancelled = std::make_shared<std::atomic_bool>(false);
    m_elapsed.start();

    emit progressUpdated(0, m_total, 0);
    emit logLine(QStringLiteral("Round-robin scheduler: one query at a time across %1 resolver(s).").arg(m_resolvers.size()));
    emit logLine(QStringLiteral("Global inter-query delay: %1 ms.").arg(m_interQueryDelayMs));
    if (!m_primeCache) {
        emit logLine(QStringLiteral("Cache warm-up skipped for this pass; using cache state from earlier pass(es)."));
    }
    if (includeUncached) {
        emit logLine(QStringLiteral("Uncached pass enabled: random labels under benchmark site domains will be measured after cached results."));
    }
    const bool summaryLogging = m_verboseLogging || m_resolvers.size() <= 250;
    if (!summaryLogging) {
        emit logLine(QStringLiteral("Per-resolver summary log lines suppressed for this large run. Enable Verbose Log to show every resolver."));
    }

    if (m_resolvers.isEmpty()) {
        finishAll();
        return;
    }

    m_threadPool.start(new BenchmarkRunnerTask(
        QPointer<BenchmarkController>(this),
        m_resolvers,
        m_sampleCount,
        m_interQueryDelayMs,
        m_domains,
        m_primeCache,
        includeUncached,
        m_verboseLogging,
        summaryLogging,
        m_cancelled));
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
    m_threadPool.waitForDone(stopWaitMs);
    emit logLine(QStringLiteral("Benchmark stopped."));
    emit benchmarkFinished();
}

bool BenchmarkController::isRunning() const
{
    return m_running;
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
    if (m_finishedResolvers >= 1) {
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
    m_threadPool.waitForDone(stopWaitMs);
    emit progressUpdated(m_completed, m_total, m_elapsed.elapsed());
    emit logLine(QStringLiteral("Benchmark complete."));
    emit benchmarkFinished();
}
