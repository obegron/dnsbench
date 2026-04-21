#pragma once

#include <QMetaType>
#include <QVector>

class Statistics {
public:
    double medianMs = 0.0;
    double p90Ms = 0.0;
    double meanMs = 0.0;
    double stddevMs = 0.0;
    double minMs = 0.0;
    double maxMs = 0.0;
    double lossPercent = 0.0;
    int successCount = 0;
    int lossCount = 0;
    int totalCount = 0;

    bool hasSamples() const { return successCount > 0; }

    static Statistics fromSamples(const QVector<qint64>& rttSamplesMs, int expectedTotal);
};

Q_DECLARE_METATYPE(Statistics)
