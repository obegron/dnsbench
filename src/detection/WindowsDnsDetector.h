#pragma once

#include "detection/SystemDnsDetector.h"

class WindowsDnsDetector final : public SystemDnsDetector {
public:
    QList<ResolverEntry> detect() override;
};
