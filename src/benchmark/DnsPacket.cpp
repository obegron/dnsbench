#include "benchmark/DnsPacket.h"

#include <QStringList>
#include <QtEndian>

namespace {

void appendUInt16(QByteArray& out, quint16 value)
{
    const quint16 be = qToBigEndian(value);
    out.append(reinterpret_cast<const char*>(&be), sizeof(be));
}

QString normalizeDomain(QString domain)
{
    domain = domain.trimmed();
    while (domain.endsWith(QLatin1Char('.'))) {
        domain.chop(1);
    }
    return domain.toLower();
}

bool appendName(QByteArray& packet, const QString& domain)
{
    const QString normalized = normalizeDomain(domain);
    if (normalized.isEmpty()) {
        return false;
    }

    const QStringList labels = normalized.split(QLatin1Char('.'), Qt::KeepEmptyParts);
    int wireLength = 1; // root label
    for (const QString& label : labels) {
        const QByteArray utf8 = label.toUtf8();
        if (utf8.isEmpty() || utf8.size() > 63) {
            return false;
        }
        wireLength += 1 + utf8.size();
        if (wireLength > 255) {
            return false;
        }
        packet.append(static_cast<char>(utf8.size()));
        packet.append(utf8);
    }
    packet.append('\0');
    return true;
}

bool readName(const QByteArray& packet, int* offset, QString* outName)
{
    QStringList labels;
    int current = *offset;
    int jumps = 0;
    bool jumped = false;

    while (current >= 0 && current < packet.size()) {
        const quint8 length = static_cast<quint8>(packet.at(current));
        if ((length & 0xc0) == 0xc0) {
            if (current + 1 >= packet.size() || ++jumps > 16) {
                return false;
            }
            const quint16 pointer = static_cast<quint16>(((length & 0x3f) << 8)
                | static_cast<quint8>(packet.at(current + 1)));
            if (!jumped) {
                *offset = current + 2;
                jumped = true;
            }
            current = pointer;
            continue;
        }
        if ((length & 0xc0) != 0 || current + 1 + length > packet.size()) {
            return false;
        }
        ++current;
        if (length == 0) {
            if (!jumped) {
                *offset = current;
            }
            *outName = labels.join(QLatin1Char('.')).toLower();
            return true;
        }
        labels.push_back(QString::fromUtf8(packet.constData() + current, length));
        current += length;
    }

    return false;
}

quint16 readUInt16(const QByteArray& packet, int offset)
{
    return qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + offset));
}

}

QByteArray DnsPacket::buildQuery(const QString& domain, quint16 transactionId, quint16 qtype)
{
    QByteArray packet;
    packet.reserve(12 + domain.size() + 17);

    appendUInt16(packet, transactionId);
    appendUInt16(packet, 0x0100); // recursion desired
    appendUInt16(packet, 1);      // QDCOUNT
    appendUInt16(packet, 0);      // ANCOUNT
    appendUInt16(packet, 0);      // NSCOUNT
    appendUInt16(packet, 1);      // ARCOUNT (EDNS0 OPT)

    // This builds a raw DNS wire-format QNAME. The OS resolver and resolv.conf
    // search domains are not consulted, so benchmarks use the requested name.
    if (!appendName(packet, domain)) {
        return {};
    }
    appendUInt16(packet, qtype);
    appendUInt16(packet, 1); // IN

    // OPT pseudo-RR with DO=1 so validating resolvers can advertise DNSSEC state
    // in the response, including the AD bit when appropriate.
    packet.append('\0');         // NAME root
    appendUInt16(packet, 41);    // TYPE OPT
    appendUInt16(packet, 1232);  // UDP payload size
    appendUInt16(packet, 0);     // EXTENDED-RCODE + VERSION
    appendUInt16(packet, 0x8000); // DO bit
    appendUInt16(packet, 0);     // RDLEN

    return packet;
}

bool DnsPacket::isValidResponse(const QByteArray& packet, quint16 transactionId)
{
    return isValidResponse(packet, transactionId, {}, 1);
}

bool DnsPacket::isValidResponse(const QByteArray& packet, quint16 transactionId, const QString& expectedDomain, quint16 qtype)
{
    if (packet.size() < 12) {
        return false;
    }

    const auto id = readUInt16(packet, 0);
    const auto flags = readUInt16(packet, 2);
    const auto qdCount = readUInt16(packet, 4);

    const bool isResponse = (flags & 0x8000) != 0;
    const bool standardQuery = (flags & 0x7800) == 0;
    const bool notTruncated = (flags & 0x0200) == 0;
    const bool noError = (flags & 0x000f) == 0;
    if (id != transactionId || !isResponse || !standardQuery || !notTruncated || !noError || qdCount != 1) {
        return false;
    }

    int offset = 12;
    QString responseDomain;
    if (!readName(packet, &offset, &responseDomain) || offset + 4 > packet.size()) {
        return false;
    }

    if (!expectedDomain.trimmed().isEmpty() && responseDomain != normalizeDomain(expectedDomain)) {
        return false;
    }

    return readUInt16(packet, offset) == qtype && readUInt16(packet, offset + 2) == 1;
}

bool DnsPacket::hasExpectedResponseId(const QByteArray& packet, quint16 transactionId)
{
    if (packet.size() < 4) {
        return false;
    }

    const auto id = readUInt16(packet, 0);
    const auto flags = readUInt16(packet, 2);
    return id == transactionId && ((flags & 0x8000) != 0);
}

bool DnsPacket::authenticatedDataBit(const QByteArray& packet)
{
    if (packet.size() < 4) {
        return false;
    }

    const auto flags = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 2));
    return (flags & 0x0020) != 0;
}
