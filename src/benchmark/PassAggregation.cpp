#include "benchmark/PassAggregation.h"

#include <algorithm>

QVector<ResolverSamplePoint> combinePassSamples(
    const QVector<QVector<ResolverSamplePoint>>& passSamples,
    const QVector<Statistics>& passStats)
{
    QVector<ResolverSamplePoint> combined;
    int offset = 0;
    const int passCount = std::max(passSamples.size(), passStats.size());
    for (int pass = 0; pass < passCount; ++pass) {
        const QVector<ResolverSamplePoint> samples = pass < passSamples.size()
            ? passSamples.at(pass)
            : QVector<ResolverSamplePoint>();
        const int expectedCount = pass < passStats.size()
            ? passStats.at(pass).totalCount
            : samples.size();

        const int recordedCount = std::max(expectedCount, static_cast<int>(samples.size()));
        combined.reserve(combined.size() + recordedCount);
        QVector<bool> recorded(recordedCount, false);
        for (ResolverSamplePoint sample : samples) {
            sample.passIndex = pass;
            const int localIndex = std::max(0, sample.sampleIndex);
            sample.sampleIndex = offset + localIndex;
            if (localIndex >= recorded.size()) {
                recorded.resize(localIndex + 1);
            }
            recorded[localIndex] = true;
            combined.push_back(sample);
        }
        for (int sample = 0; sample < expectedCount; ++sample) {
            if (!recorded.at(sample)) {
                combined.push_back({offset + sample, 0, false, QStringLiteral("Pass ended before this sample was measured"), pass});
            }
        }
        offset += expectedCount;
    }
    std::sort(combined.begin(), combined.end(), [](const ResolverSamplePoint& left, const ResolverSamplePoint& right) {
        return left.sampleIndex < right.sampleIndex;
    });
    return combined;
}

Statistics aggregateStatsForPasses(
    const QVector<QVector<ResolverSamplePoint>>& passSamples,
    const QVector<Statistics>& passStats)
{
    QVector<qint64> rtts;
    int expectedTotal = 0;
    for (const Statistics& stats : passStats) {
        expectedTotal += stats.totalCount;
    }
    if (passStats.isEmpty()) {
        for (const QVector<ResolverSamplePoint>& samples : passSamples) {
            expectedTotal += samples.size();
        }
    }
    for (const QVector<ResolverSamplePoint>& samples : passSamples) {
        for (const ResolverSamplePoint& sample : samples) {
            if (sample.success) {
                rtts.push_back(sample.rttMs);
            }
        }
    }
    return Statistics::fromSamples(rtts, expectedTotal);
}

ResolverStatus aggregateStatusForPasses(const QVector<ResolverStatus>& passStatuses)
{
    if (passStatuses.isEmpty()) {
        return ResolverStatus::Idle;
    }
    if (passStatuses.contains(ResolverStatus::Failed)) {
        return ResolverStatus::Failed;
    }
    if (passStatuses.contains(ResolverStatus::Stopped)) {
        return ResolverStatus::Stopped;
    }
    if (passStatuses.contains(ResolverStatus::Sidelined)) {
        return ResolverStatus::Sidelined;
    }
    return std::all_of(passStatuses.cbegin(), passStatuses.cend(), [](ResolverStatus status) {
        return status == ResolverStatus::Finished;
    })
        ? ResolverStatus::Finished
        : ResolverStatus::Idle;
}
