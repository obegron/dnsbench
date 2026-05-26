#include "detection/SystemDnsDetector.h"

#if defined(Q_OS_LINUX)
#include "detection/LinuxDnsDetector.h"
#elif defined(Q_OS_MACOS)
#include "detection/MacDnsDetector.h"
#endif

std::unique_ptr<SystemDnsDetector> createSystemDnsDetector()
{
#if defined(Q_OS_LINUX)
    return std::make_unique<LinuxDnsDetector>();
#elif defined(Q_OS_MACOS)
    return std::make_unique<MacDnsDetector>();
#else
    return nullptr;
#endif
}
