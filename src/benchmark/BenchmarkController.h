#pragma once

#include "benchmark/BaseResolver.h"
#include "benchmark/Statistics.h"
#include "model/ResolverEntry.h"

#include <QElapsedTimer>
#include <QObject>
#include <QQueue>
#include <QScopedPointer>

class BenchmarkController : public QObject {
    Q_OBJECT

public:
    explicit BenchmarkController(QObject* parent = nullptr);

    void start(const QList<ResolverEntry>& resolvers, int sampleCount, QStringList domains);
    void stop();
    bool isRunning() const;

signals:
    void progressUpdated(int completed, int total, qint64 elapsedMs);
    void resolverFinished(const QString& resolverId, const Statistics& stats);
    void resolverStatusChanged(const QString& resolverId, ResolverStatus status);
    void logLine(const QString& line);
    void benchmarkFinished();

private:
    QList<ResolverEntry> m_resolvers;
    QStringList m_domains;
    int m_sampleCount = 250;
    int m_currentResolver = -1;
    int m_currentSample = 0;
    int m_completed = 0;
    int m_total = 0;
    bool m_running = false;
    QVector<qint64> m_currentSamples;
    QScopedPointer<BaseResolver> m_resolver;
    QElapsedTimer m_elapsed;

    void startNextResolver();
    void runWarmup(int completed, int successes);
    void runNextSample();
    void finishCurrentResolver();
    void finishAll();
    BaseResolver* createResolver(const ResolverEntry& entry, int timeoutMs);
    QString domainForSample(int sampleIndex) const;
};
