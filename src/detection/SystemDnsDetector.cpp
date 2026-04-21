#include "detection/SystemDnsDetector.h"

#if defined(Q_OS_LINUX)
#include "detection/LinuxDnsDetector.h"
#endif

std::unique_ptr<SystemDnsDetector> createSystemDnsDetector()
{
#if defined(Q_OS_LINUX)
    return std::make_unique<LinuxDnsDetector>();
#else
    return nullptr;
#endif
}
