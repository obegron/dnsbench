#pragma once

#include "benchmark/BaseResolver.h"
#include "benchmark/Statistics.h"
#include "model/ResolverEntry.h"

#include <QElapsedTimer>
#include <QObject>
#include <QThreadPool>
#include <QTimer>

#include <atomic>
#include <memory>

class ResolverBenchmarkTask;

class BenchmarkController : public QObject {
    Q_OBJECT

public:
    explicit BenchmarkController(QObject* parent = nullptr);

    void start(const QList<ResolverEntry>& resolvers, int sampleCount, int interQueryDelayMs, QStringList domains);
    void stop();
    bool isRunning() const;
    void setMaxConcurrentResolvers(int maxConcurrentResolvers);
    void setVerboseLogging(bool verboseLogging);

signals:
    void progressUpdated(int completed, int total, qint64 elapsedMs);
    void resolverFinished(const QString& resolverId, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples);
    void resolverStatusChanged(const QString& resolverId, ResolverStatus status);
    void logLine(const QString& line);
    void benchmarkFinished();

private:
    friend class ResolverBenchmarkTask;

    QList<ResolverEntry> m_resolvers;
    QStringList m_domains;
    int m_sampleCount = 250;
    int m_interQueryDelayMs = 50;
    int m_completed = 0;
    int m_total = 0;
    int m_finishedResolvers = 0;
    qint64 m_lastProgressEmitMs = 0;
    bool m_running = false;
    bool m_verboseLogging = false;
    QThreadPool m_threadPool;
    QTimer m_submitTimer;
    std::shared_ptr<std::atomic_bool> m_cancelled;
    QElapsedTimer m_elapsed;
    int m_nextSubmitIndex = 0;

    void handleTaskProgress(int completedDelta);
    void handleTaskComplete();
    void submitMoreResolvers();
    void finishAll();
};
