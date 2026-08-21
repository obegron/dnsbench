#include "benchmark/PassAggregation.h"

#include <QTest>

class PassAggregationTest : public QObject {
    Q_OBJECT

private slots:
    void includesSidelinedPassesAsLoss()
    {
        const QVector<QVector<ResolverSamplePoint>> samples = {
            {{0, 10, true, {}, 0}, {1, 20, true, {}, 0}},
            {{0, 0, false, QStringLiteral("timeout"), 1}},
        };
        const QVector<Statistics> stats = {
            Statistics::fromSamples({10, 20}, 2),
            Statistics::fromSamples({}, 2),
        };

        const Statistics aggregate = aggregateStatsForPasses(samples, stats);
        QCOMPARE(aggregate.totalCount, 4);
        QCOMPARE(aggregate.successCount, 2);
        QCOMPARE(aggregate.lossCount, 2);
        QCOMPARE(aggregate.lossPercent, 50.0);
        QCOMPARE(aggregate.medianMs, 15.0);

        const QVector<ResolverSamplePoint> combined = combinePassSamples(samples, stats);
        QCOMPARE(combined.size(), 4);
        QCOMPARE(combined.at(2).passIndex, 1);
        QVERIFY(!combined.at(2).success);
        QCOMPARE(combined.at(3).sampleIndex, 3);
        QVERIFY(!combined.at(3).success);
    }

    void preservesNonFinishedPassStatus()
    {
        QCOMPARE(
            aggregateStatusForPasses({ResolverStatus::Finished, ResolverStatus::Sidelined, ResolverStatus::Finished}),
            ResolverStatus::Sidelined);
        QCOMPARE(
            aggregateStatusForPasses({ResolverStatus::Finished, ResolverStatus::Finished}),
            ResolverStatus::Finished);
        QCOMPARE(
            aggregateStatusForPasses({ResolverStatus::Finished, ResolverStatus::Failed}),
            ResolverStatus::Failed);
    }
};

QTEST_GUILESS_MAIN(PassAggregationTest)
#include "test_pass_aggregation.moc"
