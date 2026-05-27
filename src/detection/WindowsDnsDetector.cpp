#include "detection/WindowsDnsDetector.h"

#include "model/ResolverModel.h"

#include <QHostAddress>
#include <QSet>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>

#include <memory>

namespace {

QString addressFromSockaddr(const sockaddr* socketAddress)
{
    if (!socketAddress) {
        return {};
    }

    if (socketAddress->sa_family == AF_INET) {
        const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(socketAddress);
        return QHostAddress(ntohl(ipv4->sin_addr.s_addr)).toString();
    }

    if (socketAddress->sa_family == AF_INET6) {
        const auto* ipv6 = reinterpret_cast<const sockaddr_in6*>(socketAddress);
        Q_IPV6ADDR address;
        for (int i = 0; i < 16; ++i) {
            address[i] = ipv6->sin6_addr.u.Byte[i];
        }
        return QHostAddress(address).toString();
    }

    return {};
}

void collectDnsServers(IP_ADAPTER_ADDRESSES* adapters, bool onlyActive, QStringList& addresses)
{
    for (IP_ADAPTER_ADDRESSES* adapter = adapters; adapter; adapter = adapter->Next) {
        if (onlyActive && adapter->OperStatus != IfOperStatusUp) {
            continue;
        }
        if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        for (IP_ADAPTER_DNS_SERVER_ADDRESS* dns = adapter->FirstDnsServerAddress; dns; dns = dns->Next) {
            const QString address = addressFromSockaddr(dns->Address.lpSockaddr);
            if (!address.isEmpty()) {
                addresses.push_back(address);
            }
        }
    }
}

QList<ResolverEntry> entriesFromAddresses(const QStringList& addresses)
{
    QList<ResolverEntry> result;
    QSet<QString> seen;

    for (const QString& addressText : addresses) {
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
        result.push_back(entry);
    }

    return result;
}

}

QList<ResolverEntry> WindowsDnsDetector::detect()
{
    ULONG bufferLength = 15 * 1024;
    auto buffer = std::make_unique<unsigned char[]>(bufferLength);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get());

    constexpr ULONG flags = GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_FRIENDLY_NAME;

    ULONG result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferLength);
    if (result == ERROR_BUFFER_OVERFLOW) {
        buffer = std::make_unique<unsigned char[]>(bufferLength);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.get());
        result = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, adapters, &bufferLength);
    }

    if (result != NO_ERROR) {
        return {};
    }

    QStringList addresses;
    collectDnsServers(adapters, true, addresses);
    if (addresses.isEmpty()) {
        collectDnsServers(adapters, false, addresses);
    }

    return entriesFromAddresses(addresses);
}
