#pragma once

#include <QByteArray>
#include <QString>

namespace DnsPacket {

QByteArray buildQuery(const QString& domain, quint16 transactionId, quint16 qtype = 1);
bool isValidResponse(const QByteArray& packet, quint16 transactionId);
bool authenticatedDataBit(const QByteArray& packet);

}
