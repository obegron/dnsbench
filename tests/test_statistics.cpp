#include "benchmark/Statistics.h"

#include <QTest>

class StatisticsTest : public QObject {
    Q_OBJECT

private slots:
    void computesOddMedianAndLoss()
    {
        const Statistics stats = Statistics::fromSamples({10, 30, 20}, 5);
        QCOMPARE(stats.successCount, 3);
        QCOMPARE(stats.lossCount, 2);
        QCOMPARE(stats.totalCount, 5);
        QCOMPARE(stats.medianMs, 20.0);
        QCOMPARE(stats.meanMs, 20.0);
        QCOMPARE(stats.minMs, 10.0);
        QCOMPARE(stats.maxMs, 30.0);
        QCOMPARE(stats.lossPercent, 40.0);
    }

    void computesEvenMedianAndPopulationStddev()
    {
        const Statistics stats = Statistics::fromSamples({2, 4, 4, 4, 5, 5, 7, 9}, 8);
        QCOMPARE(stats.medianMs, 4.5);
        QCOMPARE(stats.meanMs, 5.0);
        QCOMPARE(stats.stddevMs, 2.0);
    }

    void handlesAllLoss()
    {
        const Statistics stats = Statistics::fromSamples({}, 3);
        QCOMPARE(stats.successCount, 0);
        QCOMPARE(stats.lossCount, 3);
        QCOMPARE(stats.lossPercent, 100.0);
        QVERIFY(!stats.hasSamples());
    }
};

QTEST_GUILESS_MAIN(StatisticsTest)
#include "test_statistics.moc"
