#include "export/ResultExporter.h"

#include "model/ResolverModel.h"

#include <QTest>

namespace {

ResolverEntry measuredEntry()
{
    ResolverEntry entry;
    entry.address = QStringLiteral("1.1.1.1");
    entry.displayName = QStringLiteral("Measured");
    entry.protocol = ResolverProtocol::IPv4;
    entry.port = 53;
    entry.id = ResolverModel::makeId(entry);
    entry.status = ResolverStatus::Finished;
    entry.stats = Statistics::fromSamples({5}, 1);
    return entry;
}

}

class ResultExporterTest : public QObject {
    Q_OBJECT

private slots:
    void marksUnmeasuredUncachedFieldsAsUnavailable()
    {
        const QString table = ResultExporter::toTextTable({measuredEntry()});
        QVERIFY(table.contains(QStringLiteral("| 5.0 | 5.0 | 0.0% | - | - | - |")));

        const QString csv = ResultExporter::toCsv({measuredEntry()});
        QVERIFY(csv.contains(QStringLiteral(",5.0,5.0,5.0,0.0,5.0,5.0,0.0,-,-,-,-,-,-,-,")));
    }

    void distinguishesAllLossFromMissingMeasurements()
    {
        ResolverEntry entry = measuredEntry();
        entry.stats = Statistics::fromSamples({}, 2);

        const QString table = ResultExporter::toTextTable({entry});
        QVERIFY(table.contains(QStringLiteral("| - | - | 100.0% | - | - | - |")));
    }
};

QTEST_GUILESS_MAIN(ResultExporterTest)
#include "test_result_exporter.moc"
