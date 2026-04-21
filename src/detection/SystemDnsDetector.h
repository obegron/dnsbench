#pragma once

#include "model/ResolverEntry.h"

#include <QList>

class SystemDnsDetector {
public:
    virtual ~SystemDnsDetector() = default;
    virtual QList<ResolverEntry> detect() = 0;
};
