#include "export/ResultExporter.h"

#include <QFile>
#include <QTextStream>

namespace {

QString csvEscape(QString value)
{
    if (value.contains(QLatin1Char('"')) || value.contains(QLatin1Char(',')) || value.contains(QLatin1Char('\n'))) {
        value.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        return QStringLiteral("\"%1\"").arg(value);
    }
    return value;
}

QString stat(double value)
{
    return QString::number(value, 'f', 1);
}

bool saveText(const QString& path, const QString& content, QString* error)
{
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate)) {
        if (error) {
            *error = file.errorString();
        }
        return false;
    }

    QTextStream stream(&file);
    stream << content;
    return true;
}

}

QString ResultExporter::toCsv(const QList<ResolverEntry>& entries)
{
    QString out;
    QTextStream stream(&out);
    stream << "Display Name,Address,Protocol,Median (ms),Mean (ms),Stddev,Min,Max,Loss (%),Status\n";
    for (const ResolverEntry& entry : entries) {
        stream << csvEscape(entry.effectiveName()) << ','
               << csvEscape(entry.address) << ','
               << protocolToString(entry.protocol) << ','
               << stat(entry.stats.medianMs) << ','
               << stat(entry.stats.meanMs) << ','
               << stat(entry.stats.stddevMs) << ','
               << stat(entry.stats.minMs) << ','
               << stat(entry.stats.maxMs) << ','
               << stat(entry.stats.lossPercent) << ','
               << statusToString(entry.status) << '\n';
    }
    return out;
}

QString ResultExporter::toTextTable(const QList<ResolverEntry>& entries)
{
    QString out;
    QTextStream stream(&out);
    stream << QStringLiteral("%1  %2  %3  %4  %5  %6  %7\n")
                  .arg(QStringLiteral("Name"), -24)
                  .arg(QStringLiteral("Address"), -28)
                  .arg(QStringLiteral("Proto"), -5)
                  .arg(QStringLiteral("Median"), 8)
                  .arg(QStringLiteral("Mean"), 8)
                  .arg(QStringLiteral("Loss"), 7)
                  .arg(QStringLiteral("Status"), -10);
    stream << QString(100, QLatin1Char('-')) << '\n';
    for (const ResolverEntry& entry : entries) {
        stream << QStringLiteral("%1  %2  %3  %4  %5  %6  %7\n")
                      .arg(entry.effectiveName().left(24), -24)
                      .arg(entry.address.left(28), -28)
                      .arg(protocolToString(entry.protocol), -5)
                      .arg(stat(entry.stats.medianMs), 8)
                      .arg(stat(entry.stats.meanMs), 8)
                      .arg(stat(entry.stats.lossPercent), 7)
                      .arg(statusToString(entry.status), -10);
    }
    return out;
}

bool ResultExporter::saveCsv(const QString& path, const QList<ResolverEntry>& entries, QString* error)
{
    return saveText(path, toCsv(entries), error);
}

bool ResultExporter::saveTextTable(const QString& path, const QList<ResolverEntry>& entries, QString* error)
{
    return saveText(path, toTextTable(entries), error);
}
