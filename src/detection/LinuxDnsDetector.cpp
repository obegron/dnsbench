#include "detection/LinuxDnsDetector.h"

#include "model/ResolverModel.h"

#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>

namespace {

QString stripScopeId(QString value)
{
    const int percent = value.indexOf(QLatin1Char('%'));
    if (percent >= 0) {
        value.truncate(percent);
    }
    return value;
}

bool isIpAddress(const QString& value)
{
    QHostAddress address;
    return address.setAddress(stripScopeId(value.trimmed()));
}

void collectAddressStrings(const QJsonValue& value, QStringList& out)
{
    if (value.isString()) {
        const QString text = value.toString().trimmed();
        if (isIpAddress(text)) {
            out.push_back(stripScopeId(text));
        }
        return;
    }

    if (value.isArray()) {
        const QJsonArray array = value.toArray();
        for (const QJsonValue& child : array) {
            collectAddressStrings(child, out);
        }
        return;
    }

    if (value.isObject()) {
        const QJsonObject object = value.toObject();
        for (auto it = object.begin(); it != object.end(); ++it) {
            collectAddressStrings(it.value(), out);
        }
    }
}

}

QList<ResolverEntry> LinuxDnsDetector::detect()
{
    QList<ResolverEntry> resolvedEntries;
    QProcess resolvectl;
    resolvectl.start(QStringLiteral("resolvectl"), {QStringLiteral("status"), QStringLiteral("--json=short")});
    if (resolvectl.waitForFinished(1500) && resolvectl.exitStatus() == QProcess::NormalExit && resolvectl.exitCode() == 0) {
        resolvedEntries = parseResolvectlJson(resolvectl.readAllStandardOutput());
    }

    if (!resolvedEntries.isEmpty()) {
        return resolvedEntries;
    }

    QFile file(QStringLiteral("/etc/resolv.conf"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    return parseResolvConf(file.readAll());
}

QList<ResolverEntry> LinuxDnsDetector::parseResolvConf(const QByteArray& content)
{
    QStringList addresses;
    const QString text = QString::fromUtf8(content);
    const QStringList lines = text.split(QLatin1Char('\n'));
    const QRegularExpression whitespace(QStringLiteral("\\s+"));

    for (QString line : lines) {
        const int hash = line.indexOf(QLatin1Char('#'));
        const int semicolon = line.indexOf(QLatin1Char(';'));
        int commentStart = -1;
        if (hash >= 0 && semicolon >= 0) {
            commentStart = std::min(hash, semicolon);
        } else {
            commentStart = std::max(hash, semicolon);
        }
        if (commentStart >= 0) {
            line.truncate(commentStart);
        }

        const QStringList parts = line.trimmed().split(whitespace, Qt::SkipEmptyParts);
        if (parts.size() >= 2 && parts.first() == QLatin1String("nameserver") && isIpAddress(parts.at(1))) {
            addresses.push_back(stripScopeId(parts.at(1)));
        }
    }

    return entriesFromAddresses(addresses, QStringLiteral("resolv.conf"));
}

QList<ResolverEntry> LinuxDnsDetector::parseResolvectlJson(const QByteArray& content)
{
    QJsonParseError error;
    const QJsonDocument document = QJsonDocument::fromJson(content, &error);
    if (error.error != QJsonParseError::NoError || document.isNull()) {
        return {};
    }

    QStringList addresses;
    collectAddressStrings(document.isArray() ? QJsonValue(document.array()) : QJsonValue(document.object()), addresses);
    return entriesFromAddresses(addresses, QStringLiteral("systemd-resolved"));
}

QList<ResolverEntry> LinuxDnsDetector::entriesFromAddresses(const QStringList& addresses, const QString& sourceLabel)
{
    QList<ResolverEntry> result;
    QSet<QString> seen;

    for (const QString& raw : addresses) {
        const QString addressText = stripScopeId(raw.trimmed());
        QHostAddress address;
        if (!address.setAddress(addressText)) {
            continue;
        }

        const QString key = address.toString();
        if (seen.contains(key)) {
            continue;
        }
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
        Q_UNUSED(sourceLabel);
        result.push_back(entry);
    }

    return result;
}
