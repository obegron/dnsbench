#include "benchmark/Statistics.h"

#include <algorithm>
#include <cmath>
#include <limits>

Statistics Statistics::fromSamples(const QVector<qint64>& rttSamplesMs, int expectedTotal)
{
    Statistics result;
    result.totalCount = std::max(expectedTotal, static_cast<int>(rttSamplesMs.size()));
    result.successCount = rttSamplesMs.size();
    result.lossCount = std::max(0, result.totalCount - result.successCount);

    if (result.totalCount > 0) {
        result.lossPercent = (static_cast<double>(result.lossCount) / result.totalCount) * 100.0;
    }

    if (rttSamplesMs.isEmpty()) {
        return result;
    }

    QVector<qint64> sorted = rttSamplesMs;
    std::sort(sorted.begin(), sorted.end());

    const int n = sorted.size();
    if (n % 2 == 1) {
        result.medianMs = static_cast<double>(sorted[n / 2]);
    } else {
        result.medianMs = (static_cast<double>(sorted[(n / 2) - 1]) + static_cast<double>(sorted[n / 2])) / 2.0;
    }

    double sum = 0.0;
    result.minMs = static_cast<double>(sorted.front());
    result.maxMs = static_cast<double>(sorted.back());
    for (qint64 value : sorted) {
        sum += static_cast<double>(value);
    }

    result.meanMs = sum / n;

    double varianceSum = 0.0;
    for (qint64 value : sorted) {
        const double diff = static_cast<double>(value) - result.meanMs;
        varianceSum += diff * diff;
    }
    result.stddevMs = std::sqrt(varianceSum / n);

    return result;
}
