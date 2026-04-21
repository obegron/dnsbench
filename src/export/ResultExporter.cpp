#include "export/ResultExporter.h"

#include <QFile>
#include <QHash>
#include <QTextStream>

#include <algorithm>

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

QHash<QString, int> ranksFor(const QList<ResolverEntry>& entries)
{
    QList<ResolverEntry> ranked;
    for (const ResolverEntry& entry : entries) {
        if (entry.status == ResolverStatus::Finished && entry.stats.hasSamples()) {
            ranked.push_back(entry);
        }
    }

    std::sort(ranked.begin(), ranked.end(), [](const ResolverEntry& left, const ResolverEntry& right) {
        if (left.stats.medianMs == right.stats.medianMs) {
            return left.stats.meanMs < right.stats.meanMs;
        }
        return left.stats.medianMs < right.stats.medianMs;
    });

    QHash<QString, int> ranks;
    for (int i = 0; i < ranked.size(); ++i) {
        ranks.insert(ranked.at(i).id, i + 1);
    }
    return ranks;
}

QString verdictFor(const ResolverEntry& entry, int rank)
{
    if (entry.status == ResolverStatus::Sidelined) {
        return QStringLiteral("Sidelined");
    }
    if (entry.status != ResolverStatus::Finished || !entry.stats.hasSamples()) {
        return QStringLiteral("No result");
    }
    if (entry.stats.lossPercent > 1.0) {
        return QStringLiteral("Unreliable");
    }
    if (rank == 1) {
        return QStringLiteral("Fastest");
    }
    if (entry.stats.stddevMs > std::max(20.0, entry.stats.medianMs * 3.0)) {
        return QStringLiteral("Spiky latency");
    }
    if (entry.stats.medianMs <= 10.0) {
        return QStringLiteral("Very fast");
    }
    if (entry.stats.medianMs <= 25.0) {
        return QStringLiteral("Fast");
    }
    return QStringLiteral("Measured");
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
    const QHash<QString, int> ranks = ranksFor(entries);
    QString out;
    QTextStream stream(&out);
    stream << "Rank,Display Name,Address,Protocol,Median (ms),P90 (ms),Mean (ms),Stddev,Min,Max,Loss (%),Status,Verdict\n";
    for (const ResolverEntry& entry : entries) {
        const int rank = ranks.value(entry.id, 0);
        stream << (rank > 0 ? QString::number(rank) : QString()) << ','
               << csvEscape(entry.effectiveName()) << ','
               << csvEscape(entry.address) << ','
               << protocolToString(entry.protocol) << ','
               << stat(entry.stats.medianMs) << ','
               << stat(entry.stats.p90Ms) << ','
               << stat(entry.stats.meanMs) << ','
               << stat(entry.stats.stddevMs) << ','
               << stat(entry.stats.minMs) << ','
               << stat(entry.stats.maxMs) << ','
               << stat(entry.stats.lossPercent) << ','
               << statusToString(entry.status) << ','
               << csvEscape(verdictFor(entry, rank)) << '\n';
    }
    return out;
}

QString ResultExporter::toTextTable(const QList<ResolverEntry>& entries)
{
    const QHash<QString, int> ranks = ranksFor(entries);
    QString out;
    QTextStream stream(&out);
    stream << QStringLiteral("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                  .arg(QStringLiteral("#"), 3)
                  .arg(QStringLiteral("Name"), -24)
                  .arg(QStringLiteral("Address"), -28)
                  .arg(QStringLiteral("Proto"), -5)
                  .arg(QStringLiteral("Median"), 8)
                  .arg(QStringLiteral("P90"), 8)
                  .arg(QStringLiteral("Mean"), 8)
                  .arg(QStringLiteral("Loss"), 7)
                  .arg(QStringLiteral("Verdict"), -14);
    stream << QString(120, QLatin1Char('-')) << '\n';
    for (const ResolverEntry& entry : entries) {
        const int rank = ranks.value(entry.id, 0);
        stream << QStringLiteral("%1  %2  %3  %4  %5  %6  %7  %8  %9\n")
                      .arg(rank > 0 ? QString::number(rank) : QStringLiteral("-"), 3)
                      .arg(entry.effectiveName().left(24), -24)
                      .arg(entry.address.left(28), -28)
                      .arg(protocolToString(entry.protocol), -5)
                      .arg(stat(entry.stats.medianMs), 8)
                      .arg(stat(entry.stats.p90Ms), 8)
                      .arg(stat(entry.stats.meanMs), 8)
                      .arg(stat(entry.stats.lossPercent), 7)
                      .arg(verdictFor(entry, rank), -14);
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
