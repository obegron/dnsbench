#pragma once

#include "detection/SystemDnsDetector.h"

class MacDnsDetector : public SystemDnsDetector {
public:
    QList<ResolverEntry> detect() override;
};
