#pragma once

#include "benchmark/Statistics.h"
#include "model/ResolverEntry.h"

#include <QVector>

QVector<ResolverSamplePoint> combinePassSamples(
    const QVector<QVector<ResolverSamplePoint>>& passSamples,
    const QVector<Statistics>& passStats);
Statistics aggregateStatsForPasses(
    const QVector<QVector<ResolverSamplePoint>>& passSamples,
    const QVector<Statistics>& passStats);
ResolverStatus aggregateStatusForPasses(const QVector<ResolverStatus>& passStatuses);
