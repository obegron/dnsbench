#include "benchmark/BenchmarkController.h"

#include "benchmark/DohResolver.h"
#include "benchmark/DotResolver.h"
#include "benchmark/UdpResolver.h"

#include <QRandomGenerator>
#include <QTimer>

#include <algorithm>
#include <random>

BenchmarkController::BenchmarkController(QObject* parent)
    : QObject(parent)
{
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

    m_currentResolver = -1;
    m_currentSample = 0;
    m_completed = 0;
    m_total = m_resolvers.size() * m_sampleCount;
    m_running = true;
    m_elapsed.start();

    emit progressUpdated(0, m_total, 0);
    QTimer::singleShot(0, this, &BenchmarkController::startNextResolver);
}

void BenchmarkController::stop()
{
    if (!m_running) {
        return;
    }

    m_running = false;
    if (m_resolver) {
        m_resolver->cancel();
        m_resolver.reset();
    }
    emit logLine(QStringLiteral("Benchmark stopped."));
    emit benchmarkFinished();
}

bool BenchmarkController::isRunning() const
{
    return m_running;
}

void BenchmarkController::startNextResolver()
{
    if (!m_running) {
        return;
    }

    ++m_currentResolver;
    m_currentSample = 0;
    m_currentSamples.clear();
    m_resolver.reset();

    if (m_currentResolver >= m_resolvers.size()) {
        finishAll();
        return;
    }

    const ResolverEntry& entry = m_resolvers.at(m_currentResolver);
    emit resolverStatusChanged(entry.id, ResolverStatus::Running);
    emit logLine(QStringLiteral("Warming up %1 (%2).").arg(entry.effectiveName(), protocolToString(entry.protocol)));
    m_resolver.reset(createResolver(entry, 50));
    runWarmup(0, 0);
}

void BenchmarkController::runWarmup(int completed, int successes)
{
    if (!m_running || !m_resolver) {
        return;
    }

    constexpr int warmupCount = 10;
    if (completed >= warmupCount) {
        const ResolverEntry& entry = m_resolvers.at(m_currentResolver);
        if (successes < 3) {
            emit resolverStatusChanged(entry.id, ResolverStatus::Sidelined);
            emit logLine(QStringLiteral("Sidelined %1: %2/%3 warm-up responses.").arg(entry.effectiveName()).arg(successes).arg(warmupCount));
            m_completed += m_sampleCount;
            emit progressUpdated(m_completed, m_total, m_elapsed.elapsed());
            QTimer::singleShot(0, this, &BenchmarkController::startNextResolver);
            return;
        }

        emit logLine(QStringLiteral("Warm-up passed for %1: %2/%3 responses.").arg(entry.effectiveName()).arg(successes).arg(warmupCount));
        m_resolver.reset(createResolver(entry, 5000));
        runNextSample();
        return;
    }

    m_resolver->query(domainForSample(completed), [this, completed, successes](qint64 rtt, bool success) {
        Q_UNUSED(rtt);
        if (!m_running) {
            return;
        }
        QTimer::singleShot(0, this, [this, completed, successes, success]() {
            runWarmup(completed + 1, successes + (success ? 1 : 0));
        });
    });
}

void BenchmarkController::runNextSample()
{
    if (!m_running || !m_resolver) {
        return;
    }

    if (m_currentSample >= m_sampleCount) {
        finishCurrentResolver();
        return;
    }

    const QString domain = domainForSample(m_currentSample);
    const ResolverEntry& entry = m_resolvers.at(m_currentResolver);
    emit logLine(QStringLiteral("Query %1 via %2.").arg(domain, entry.effectiveName()));

    m_resolver->query(domain, [this, domain](qint64 rttMs, bool success) {
        if (!m_running) {
            return;
        }

        if (success) {
            m_currentSamples.push_back(rttMs);
            emit logLine(QStringLiteral("Response %1 in %2 ms.").arg(domain).arg(rttMs));
        } else {
            emit logLine(QStringLiteral("Timeout/failure for %1.").arg(domain));
        }

        ++m_currentSample;
        ++m_completed;
        emit progressUpdated(m_completed, m_total, m_elapsed.elapsed());
        QTimer::singleShot(0, this, &BenchmarkController::runNextSample);
    });
}

void BenchmarkController::finishCurrentResolver()
{
    const ResolverEntry& entry = m_resolvers.at(m_currentResolver);
    const Statistics stats = Statistics::fromSamples(m_currentSamples, m_sampleCount);
    emit resolverFinished(entry.id, stats);
    emit logLine(QStringLiteral("Finished %1: median %2 ms, loss %3%.")
        .arg(entry.effectiveName())
        .arg(stats.medianMs, 0, 'f', 1)
        .arg(stats.lossPercent, 0, 'f', 1));
    QTimer::singleShot(0, this, &BenchmarkController::startNextResolver);
}

void BenchmarkController::finishAll()
{
    m_running = false;
    m_resolver.reset();
    emit logLine(QStringLiteral("Benchmark complete."));
    emit benchmarkFinished();
}

BaseResolver* BenchmarkController::createResolver(const ResolverEntry& entry, int timeoutMs)
{
    switch (entry.protocol) {
    case ResolverProtocol::IPv4:
    case ResolverProtocol::IPv6:
        return new UdpResolver(entry, timeoutMs, this);
    case ResolverProtocol::DoH:
        return new DohResolver(entry, timeoutMs, this);
    case ResolverProtocol::DoT:
        return new DotResolver(entry, timeoutMs, this);
    }
    return new UdpResolver(entry, timeoutMs, this);
}

QString BenchmarkController::domainForSample(int sampleIndex) const
{
    return m_domains.at(sampleIndex % m_domains.size());
}
