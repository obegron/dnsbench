#pragma once

#include "detection/SystemDnsDetector.h"

#include <QByteArray>
#include <QString>

class LinuxDnsDetector : public SystemDnsDetector {
public:
    QList<ResolverEntry> detect() override;

    static QList<ResolverEntry> parseResolvConf(const QByteArray& content);
    static QList<ResolverEntry> parseResolvectlJson(const QByteArray& content);

private:
    static QList<ResolverEntry> entriesFromAddresses(const QStringList& addresses, const QString& sourceLabel);
};
