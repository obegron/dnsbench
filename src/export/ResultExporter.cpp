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

QString markdownEscape(QString value)
{
    value.replace(QLatin1Char('\\'), QStringLiteral("\\\\"));
    value.replace(QLatin1Char('|'), QStringLiteral("\\|"));
    value.replace(QLatin1Char('\n'), QStringLiteral("<br>"));
    return value;
}

QString formatStat(const Statistics& stats, double value, bool requiresSuccessfulSample = true)
{
    if (stats.totalCount == 0 || (requiresSuccessfulSample && stats.successCount == 0)) {
        return QStringLiteral("-");
    }
    return QString::number(value, 'f', 1);
}

bool isReliable(const ResolverEntry& entry)
{
    return entry.stats.lossPercent <= 1.0;
}

bool resultLessThan(const ResolverEntry& left, const ResolverEntry& right)
{
    const bool leftReliable = isReliable(left);
    const bool rightReliable = isReliable(right);
    if (leftReliable != rightReliable) {
        return leftReliable;
    }
    if (!leftReliable && left.stats.lossPercent != right.stats.lossPercent) {
        return left.stats.lossPercent < right.stats.lossPercent;
    }
    if (left.stats.medianMs != right.stats.medianMs) {
        return left.stats.medianMs < right.stats.medianMs;
    }
    if (left.uncachedStats.hasSamples() && right.uncachedStats.hasSamples()
        && left.uncachedStats.medianMs != right.uncachedStats.medianMs) {
        return left.uncachedStats.medianMs < right.uncachedStats.medianMs;
    }
    if (left.stats.p90Ms != right.stats.p90Ms) {
        return left.stats.p90Ms < right.stats.p90Ms;
    }
    return left.stats.meanMs < right.stats.meanMs;
}

QHash<QString, int> ranksFor(const QList<ResolverEntry>& entries)
{
    QList<ResolverEntry> ranked;
    for (const ResolverEntry& entry : entries) {
        if (entry.status == ResolverStatus::Finished && entry.stats.hasSamples()) {
            ranked.push_back(entry);
        }
    }

    std::sort(ranked.begin(), ranked.end(), resultLessThan);

    QHash<QString, int> ranks;
    for (int i = 0; i < ranked.size(); ++i) {
        ranks.insert(ranked.at(i).id, i + 1);
    }
    return ranks;
}

QString verdictFor(const ResolverEntry& entry, int rank)
{
    if (rank == 1 && entry.status == ResolverStatus::Finished && entry.stats.hasSamples() && entry.stats.lossPercent <= 1.0) {
        return QStringLiteral("Fastest");
    }
    return resolverVerdict(entry);
}

QString dnssecFor(const ResolverEntry& entry)
{
    if (entry.status == ResolverStatus::Finished && entry.stats.hasSamples()) {
        return entry.dnssecAuthenticatedDataSeen ? QStringLiteral("AD seen") : QStringLiteral("No AD");
    }
    return QStringLiteral("-");
}

bool includeInMarkdownTable(const ResolverEntry& entry)
{
    return entry.enabled && entry.status != ResolverStatus::Disabled;
}

QList<ResolverEntry> markdownEntriesFor(const QList<ResolverEntry>& entries)
{
    QList<ResolverEntry> result;
    for (const ResolverEntry& entry : entries) {
        if (includeInMarkdownTable(entry)) {
            result.push_back(entry);
        }
    }

    std::sort(result.begin(), result.end(), [](const ResolverEntry& left, const ResolverEntry& right) {
        const bool leftMeasured = left.status == ResolverStatus::Finished && left.stats.hasSamples();
        const bool rightMeasured = right.status == ResolverStatus::Finished && right.stats.hasSamples();
        if (leftMeasured != rightMeasured) {
            return leftMeasured;
        }
        if (leftMeasured && rightMeasured) {
            return resultLessThan(left, right);
        }
        if (left.status != right.status) {
            return statusToString(left.status) < statusToString(right.status);
        }
        return QString::localeAwareCompare(left.effectiveName(), right.effectiveName()) < 0;
    });
    return result;
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
    stream << "Rank,Display Name,Address,Protocol,Cached Median (ms),Cached P90 (ms),Cached Mean (ms),Cached Stddev,Cached Min,Cached Max,Cached Loss (%),Uncached Median (ms),Uncached P90 (ms),Uncached Mean (ms),Uncached Stddev,Uncached Min,Uncached Max,Uncached Loss (%),DNSSEC,Status,Verdict\n";
    for (const ResolverEntry& entry : entries) {
        const int rank = ranks.value(entry.id, 0);
        stream << (rank > 0 ? QString::number(rank) : QString()) << ','
               << csvEscape(entry.effectiveName()) << ','
               << csvEscape(entry.address) << ','
               << protocolToString(entry.protocol) << ','
               << formatStat(entry.stats, entry.stats.medianMs) << ','
               << formatStat(entry.stats, entry.stats.p90Ms) << ','
               << formatStat(entry.stats, entry.stats.meanMs) << ','
               << formatStat(entry.stats, entry.stats.stddevMs) << ','
               << formatStat(entry.stats, entry.stats.minMs) << ','
               << formatStat(entry.stats, entry.stats.maxMs) << ','
               << formatStat(entry.stats, entry.stats.lossPercent, false) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.medianMs) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.p90Ms) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.meanMs) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.stddevMs) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.minMs) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.maxMs) << ','
               << formatStat(entry.uncachedStats, entry.uncachedStats.lossPercent, false) << ','
               << csvEscape(dnssecFor(entry)) << ','
               << statusToString(entry.status) << ','
               << csvEscape(verdictFor(entry, rank)) << '\n';
    }
    return out;
}

QString ResultExporter::toTextTable(const QList<ResolverEntry>& entries)
{
    const QHash<QString, int> ranks = ranksFor(entries);
    const QList<ResolverEntry> sortedEntries = markdownEntriesFor(entries);
    QString out;
    QTextStream stream(&out);
    stream << "| Rank | Name | Address | Proto | Cached Median | Cached P90 | Cached Loss | Uncached Median | Uncached P90 | Uncached Loss | DNSSEC | Status | Verdict |\n";
    stream << "|---:|---|---|---|---:|---:|---:|---:|---:|---:|---|---|---|\n";
    for (const ResolverEntry& entry : sortedEntries) {
        const int rank = ranks.value(entry.id, 0);
        stream << "| "
               << (rank > 0 ? QString::number(rank) : QStringLiteral("-")) << " | "
               << markdownEscape(entry.effectiveName()) << " | "
               << markdownEscape(entry.address) << " | "
               << protocolToString(entry.protocol) << " | "
               << formatStat(entry.stats, entry.stats.medianMs) << " | "
               << formatStat(entry.stats, entry.stats.p90Ms) << " | "
               << formatStat(entry.stats, entry.stats.lossPercent, false) << (entry.stats.totalCount > 0 ? "% | " : " | ")
               << formatStat(entry.uncachedStats, entry.uncachedStats.medianMs) << " | "
               << formatStat(entry.uncachedStats, entry.uncachedStats.p90Ms) << " | "
               << formatStat(entry.uncachedStats, entry.uncachedStats.lossPercent, false) << (entry.uncachedStats.totalCount > 0 ? "% | " : " | ")
               << markdownEscape(dnssecFor(entry)) << " | "
               << statusToString(entry.status) << " | "
               << markdownEscape(verdictFor(entry, rank)) << " |\n";
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
