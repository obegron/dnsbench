#include "detection/MacDnsDetector.h"
#include "model/ResolverModel.h"
#include <QProcess>
#include <QRegularExpression>
#include <QHostAddress>
#include <QSet>

QList<ResolverEntry> MacDnsDetector::detect()
{
    QProcess scutil;
    scutil.start(QStringLiteral("scutil"), {QStringLiteral("--dns")});
    if (!scutil.waitForFinished(1500) || scutil.exitStatus() != QProcess::NormalExit || scutil.exitCode() != 0) {
        return {};
    }

    const QString output = QString::fromUtf8(scutil.readAllStandardOutput());
    const QStringList lines = output.split(QLatin1Char('\n'));
    
    QSet<QString> addresses;
    QRegularExpression re(QStringLiteral("nameserver\\[\\d+\\]\\s*:\\s*(\\S+)"));

    for (const QString& line : lines) {
        QRegularExpressionMatch match = re.match(line);
        if (match.hasMatch()) {
            addresses.insert(match.captured(1));
        }
    }

    QList<ResolverEntry> result;
    QSet<QString> seen;
    for (const QString& addressText : addresses) {
        QHostAddress address(addressText);
        if (address.isNull()) continue;
        
        const QString key = address.toString();
        if (seen.contains(key)) continue;
        seen.insert(key);

        ResolverEntry entry;
        entry.address = key;
        entry.port = 53;
        entry.protocol = address.protocol() == QAbstractSocket::IPv6Protocol
            ? ResolverProtocol::IPv6
            : ResolverProtocol::IPv4;
        entry.displayName = QStringLiteral("%1 (System)").arg(key);
        entry.systemResolver = true;
        entry.enabled = true;
        entry.pinned = true;
        entry.id = ResolverModel::makeId(entry);
        result.push_back(entry);
    }

    return result;
}
