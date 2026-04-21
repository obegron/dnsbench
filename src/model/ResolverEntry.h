#pragma once

#include "benchmark/Statistics.h"

#include <QMetaType>
#include <QString>

enum class ResolverProtocol {
    IPv4,
    IPv6,
    DoH,
    DoT
};

enum class ResolverStatus {
    Idle,
    Running,
    Finished,
    Failed,
    Sidelined,
    Disabled
};

struct ResolverEntry {
    QString id;
    QString address;
    int port = 53;
    ResolverProtocol protocol = ResolverProtocol::IPv4;
    QString displayName;
    bool pinned = false;
    bool enabled = true;
    bool systemResolver = false;
    bool builtInResolver = false;
    ResolverStatus status = ResolverStatus::Idle;
    Statistics stats;

    QString effectiveName() const;
};

Q_DECLARE_METATYPE(ResolverProtocol)
Q_DECLARE_METATYPE(ResolverStatus)
Q_DECLARE_METATYPE(ResolverEntry)

QString protocolToString(ResolverProtocol protocol);
ResolverProtocol protocolFromString(const QString& value, bool* ok = nullptr);
QString statusToString(ResolverStatus status);
int defaultPortForProtocol(ResolverProtocol protocol);
