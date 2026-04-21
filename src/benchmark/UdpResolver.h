#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QHostAddress>

class UdpResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit UdpResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;

private:
    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
};
