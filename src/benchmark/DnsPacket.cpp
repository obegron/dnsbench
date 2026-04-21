#include "benchmark/DnsPacket.h"

#include <QRegularExpression>
#include <QStringList>
#include <QtEndian>

namespace {

void appendUInt16(QByteArray& out, quint16 value)
{
    const quint16 be = qToBigEndian(value);
    out.append(reinterpret_cast<const char*>(&be), sizeof(be));
}

}

QByteArray DnsPacket::buildQuery(const QString& domain, quint16 transactionId, quint16 qtype)
{
    QByteArray packet;
    packet.reserve(12 + domain.size() + 6);

    appendUInt16(packet, transactionId);
    appendUInt16(packet, 0x0100); // recursion desired
    appendUInt16(packet, 1);      // QDCOUNT
    appendUInt16(packet, 0);      // ANCOUNT
    appendUInt16(packet, 0);      // NSCOUNT
    appendUInt16(packet, 0);      // ARCOUNT

    const QString normalized = domain.trimmed().remove(QRegularExpression(QStringLiteral("\\.$")));
    const QStringList labels = normalized.split(QLatin1Char('.'), Qt::SkipEmptyParts);
    for (const QString& label : labels) {
        const QByteArray utf8 = label.toUtf8();
        if (utf8.size() > 63) {
            return {};
        }
        packet.append(static_cast<char>(utf8.size()));
        packet.append(utf8);
    }
    packet.append('\0');
    appendUInt16(packet, qtype);
    appendUInt16(packet, 1); // IN

    return packet;
}

bool DnsPacket::isValidResponse(const QByteArray& packet, quint16 transactionId)
{
    if (packet.size() < 12) {
        return false;
    }

    const auto id = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData()));
    const auto flags = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 2));
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
