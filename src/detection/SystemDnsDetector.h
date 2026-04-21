#pragma once

#include "model/ResolverEntry.h"

#include <QList>

#include <memory>

class SystemDnsDetector {
public:
    virtual ~SystemDnsDetector() = default;
    virtual QList<ResolverEntry> detect() = 0;
};

std::unique_ptr<SystemDnsDetector> createSystemDnsDetector();
