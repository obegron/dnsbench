#include "cli/HeadlessBenchmark.h"

#include "benchmark/BenchmarkController.h"
#include "detection/LinuxDnsDetector.h"
#include "export/ResultExporter.h"
#include "model/ResolverModel.h"

#include <QCommandLineParser>
#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QHash>
#include <QHostAddress>
#include <QSet>
#include <QTextStream>
#include <QUrl>

#include <algorithm>

namespace {

QStringList readDomainLines(QFile& file)
{
    QStringList domains;
    while (!file.atEnd()) {
        QString line = QString::fromUtf8(file.readLine()).trimmed();
        const int comment = line.indexOf(QLatin1Char('#'));
        if (comment >= 0) {
            line.truncate(comment);
            line = line.trimmed();
        }
        if (!line.isEmpty()) {
            domains.push_back(line);
        }
    }
    return domains;
}

QStringList loadDomains(int limit, const QString& filePath, QTextStream& err, bool* ok)
{
    if (ok) {
        *ok = false;
    }

    QFile file(filePath.isEmpty() ? QStringLiteral(":/test_domains.txt") : filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        if (!filePath.isEmpty()) {
            err << "--domains-file could not be opened: " << filePath << " (" << file.errorString() << ")\n";
            return {};
        }
    }

    QStringList domains = file.isOpen() ? readDomainLines(file) : QStringList();
    if (!filePath.isEmpty() && domains.isEmpty()) {
        err << "--domains-file contains no usable domains: " << filePath << '\n';
        return {};
    }
    if (domains.isEmpty()) {
        domains = {QStringLiteral("example.com"), QStringLiteral("qt.io"), QStringLiteral("cloudflare.com")};
    }
    if (limit > 0 && domains.size() > limit) {
        domains = domains.mid(0, limit);
    }
    if (ok) {
        *ok = true;
    }
    return domains;
}

bool inferProtocol(const QString& address, ResolverProtocol* protocol)
{
    QHostAddress host;
    if (host.setAddress(address)) {
        *protocol = host.protocol() == QAbstractSocket::IPv6Protocol ? ResolverProtocol::IPv6 : ResolverProtocol::IPv4;
        return true;
    }

    const QUrl url(address);
    if (url.isValid() && url.scheme() == QLatin1String("https") && !url.host().isEmpty()) {
        *protocol = ResolverProtocol::DoH;
        return true;
    }

    if (address.contains(QStringLiteral("dns-query")) || address.contains(QLatin1Char('/'))) {
        *protocol = ResolverProtocol::DoH;
        return true;
    }

    if (address.contains(QLatin1Char('.'))) {
        *protocol = ResolverProtocol::DoT;
        return true;
    }

    return false;
}

bool parseResolverSpec(const QString& spec, int index, ResolverEntry* entry, QString* error)
{
    const QStringList parts = spec.split(QLatin1Char(','), Qt::KeepEmptyParts);
    if (parts.isEmpty() || parts.first().trimmed().isEmpty()) {
        if (error) {
            *error = QStringLiteral("empty resolver spec");
        }
        return false;
    }

    entry->address = parts.at(0).trimmed();
    ResolverProtocol protocol = ResolverProtocol::IPv4;
    bool protocolKnown = inferProtocol(entry->address, &protocol);
    if (parts.size() >= 2 && !parts.at(1).trimmed().isEmpty()) {
        bool ok = false;
        protocol = protocolFromString(parts.at(1), &ok);
        if (!ok) {
            if (error) {
                *error = QStringLiteral("unknown protocol '%1'").arg(parts.at(1).trimmed());
            }
            return false;
        }
        protocolKnown = true;
    }
    if (!protocolKnown) {
        if (error) {
            *error = QStringLiteral("could not infer protocol for '%1'").arg(entry->address);
        }
        return false;
    }

    entry->protocol = protocol;
    entry->port = defaultPortForProtocol(protocol);
    if (parts.size() >= 3 && !parts.at(2).trimmed().isEmpty()) {
        bool ok = false;
        const int port = parts.at(2).trimmed().toInt(&ok);
        if (!ok || port < 1 || port > 65535) {
            if (error) {
                *error = QStringLiteral("invalid port '%1'").arg(parts.at(2).trimmed());
            }
            return false;
        }
        entry->port = port;
    }

    entry->displayName = parts.size() >= 4 && !parts.at(3).trimmed().isEmpty()
        ? parts.at(3).trimmed()
        : QStringLiteral("Resolver %1").arg(index + 1);
    entry->enabled = true;
    entry->id = ResolverModel::makeId(*entry);
    return true;
}

QList<ResolverEntry> parseManualResolvers(const QStringList& specs, QTextStream& err)
{
    QList<ResolverEntry> entries;
    for (int i = 0; i < specs.size(); ++i) {
        ResolverEntry entry;
        QString error;
        if (!parseResolverSpec(specs.at(i), i, &entry, &error)) {
            err << "Skipping resolver '" << specs.at(i) << "': " << error << '\n';
            continue;
        }
        entries.push_back(entry);
    }
    return entries;
}

void mergeUniqueResolvers(QList<ResolverEntry>* target, const QList<ResolverEntry>& source)
{
    QSet<QString> ids;
    for (const ResolverEntry& entry : std::as_const(*target)) {
        ids.insert(entry.id);
    }
    for (const ResolverEntry& entry : source) {
        if (!ids.contains(entry.id)) {
            target->push_back(entry);
            ids.insert(entry.id);
        }
    }
}

}

int runHeadlessBenchmark(QCoreApplication& app)
{
    QTextStream out(stdout);
    QTextStream err(stderr);

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Run DNS Benchmark without the GUI."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({QStringLiteral("headless"), QStringLiteral("Run without showing the GUI.")});
    parser.addOption({{QStringLiteral("r"), QStringLiteral("resolver")},
        QStringLiteral("Resolver as address[,protocol[,port[,name]]]. Repeat for multiple resolvers."),
        QStringLiteral("resolver")});
    parser.addOption({QStringLiteral("system-dns"), QStringLiteral("Benchmark detected system DNS resolvers.")});
    parser.addOption({QStringLiteral("samples"), QStringLiteral("Measured samples per resolver."), QStringLiteral("count"), QStringLiteral("250")});
    parser.addOption({QStringLiteral("delay"), QStringLiteral("Delay between queries per resolver in milliseconds."), QStringLiteral("ms"), QStringLiteral("100")});
    parser.addOption({QStringLiteral("concurrent"), QStringLiteral("Maximum resolvers benchmarked at once."), QStringLiteral("count"),
        QString::number(BenchmarkController::recommendedMaxConcurrentResolvers())});
    parser.addOption({QStringLiteral("domain-limit"), QStringLiteral("Limit test domains loaded from resources; 0 means all."), QStringLiteral("count"), QStringLiteral("0")});
    parser.addOption({QStringLiteral("domains-file"), QStringLiteral("Load benchmark domains from a text file instead of the built-in list."), QStringLiteral("path")});
    parser.addOption({QStringLiteral("csv"), QStringLiteral("Print CSV instead of a Markdown table.")});
    parser.addOption({QStringLiteral("verbose"), QStringLiteral("Print per-query benchmark log lines to stderr.")});
    parser.process(app);

    bool ok = false;
    const int samples = parser.value(QStringLiteral("samples")).toInt(&ok);
    if (!ok || samples < 1) {
        err << "--samples must be a positive integer\n";
        return 2;
    }
    const int delayMs = parser.value(QStringLiteral("delay")).toInt(&ok);
    if (!ok || delayMs < 0) {
        err << "--delay must be a non-negative integer\n";
        return 2;
    }
    const int concurrent = parser.value(QStringLiteral("concurrent")).toInt(&ok);
    if (!ok || concurrent < 1) {
        err << "--concurrent must be a positive integer\n";
        return 2;
    }
    const int domainLimit = parser.value(QStringLiteral("domain-limit")).toInt(&ok);
    if (!ok || domainLimit < 0) {
        err << "--domain-limit must be a non-negative integer\n";
        return 2;
    }

    bool domainsOk = false;
    const QStringList domains = loadDomains(domainLimit, parser.value(QStringLiteral("domains-file")), err, &domainsOk);
    if (!domainsOk) {
        return 2;
    }

    QList<ResolverEntry> entries = parseManualResolvers(parser.values(QStringLiteral("resolver")), err);
    if (parser.isSet(QStringLiteral("system-dns"))) {
        LinuxDnsDetector detector;
        mergeUniqueResolvers(&entries, detector.detect());
    }
    if (entries.isEmpty()) {
        err << "No resolvers to benchmark. Use --system-dns or --resolver address[,protocol[,port[,name]]].\n";
        return 2;
    }

    QList<ResolverEntry> results = entries;
    BenchmarkController controller;
    controller.setMaxConcurrentResolvers(concurrent);
    controller.setVerboseLogging(parser.isSet(QStringLiteral("verbose")));

    QHash<QString, int> rowById;
    for (int i = 0; i < results.size(); ++i) {
        rowById.insert(results.at(i).id, i);
    }

    QObject::connect(&controller, &BenchmarkController::resolverFinished, &app,
        [&](const QString& resolverId, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples) {
            const int row = rowById.value(resolverId, -1);
            if (row < 0) {
                return;
            }
            results[row].stats = stats;
            results[row].status = status;
            results[row].dnssecAuthenticatedDataSeen = dnssecAuthenticatedDataSeen;
            results[row].samples = samples;
        });

    if (parser.isSet(QStringLiteral("verbose"))) {
        QObject::connect(&controller, &BenchmarkController::logLine, &app, [&](const QString& line) {
            err << line << '\n';
        });
    }

    QEventLoop loop;
    QObject::connect(&controller, &BenchmarkController::benchmarkFinished, &loop, &QEventLoop::quit);

    controller.start(entries, samples, delayMs, domains);
    loop.exec();

    out << (parser.isSet(QStringLiteral("csv"))
            ? ResultExporter::toCsv(results)
            : ResultExporter::toTextTable(results));
    return 0;
}
