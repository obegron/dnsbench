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

QString stat(double value)
{
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
    stream << "Rank,Display Name,Address,Protocol,Median (ms),P90 (ms),Mean (ms),Stddev,Min,Max,Loss (%),DNSSEC,Status,Verdict\n";
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
               << csvEscape(dnssecFor(entry)) << ','
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
    stream << "| Rank | Name | Address | Proto | Median | P90 | Mean | Stddev | Min | Max | Loss | DNSSEC | Status | Verdict |\n";
    stream << "|---:|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|\n";
    for (const ResolverEntry& entry : entries) {
        const int rank = ranks.value(entry.id, 0);
        stream << "| "
               << (rank > 0 ? QString::number(rank) : QStringLiteral("-")) << " | "
               << markdownEscape(entry.effectiveName()) << " | "
               << markdownEscape(entry.address) << " | "
               << protocolToString(entry.protocol) << " | "
               << stat(entry.stats.medianMs) << " | "
               << stat(entry.stats.p90Ms) << " | "
               << stat(entry.stats.meanMs) << " | "
               << stat(entry.stats.stddevMs) << " | "
               << stat(entry.stats.minMs) << " | "
               << stat(entry.stats.maxMs) << " | "
               << stat(entry.stats.lossPercent) << "% | "
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
