#include "benchmark/DnsPacket.h"

#include <QTest>
#include <QtEndian>

class DnsPacketTest : public QObject {
    Q_OBJECT

private slots:
    void buildsMinimalAQuery()
    {
        const QByteArray packet = DnsPacket::buildQuery(QStringLiteral("example.com"), 0x1234, 1);

        QCOMPARE(packet.size(), 40);
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData())), quint16(0x1234));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 2)), quint16(0x0100));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 4)), quint16(1));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 10)), quint16(1));
        QCOMPARE(packet.mid(12, 13), QByteArray("\x07""example\x03""com\x00", 13));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 25)), quint16(1));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 27)), quint16(1));
        QCOMPARE(packet.at(29), '\0');
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 30)), quint16(41));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 32)), quint16(1232));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 34)), quint16(0));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 36)), quint16(0x8000));
        QCOMPARE(qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(packet.constData() + 38)), quint16(0));
    }

    void treatsTrailingDotAsAbsoluteQueryName()
    {
        QCOMPARE(
            DnsPacket::buildQuery(QStringLiteral("example.com."), 0x1234, 1),
            DnsPacket::buildQuery(QStringLiteral("example.com"), 0x1234, 1));
    }

    void validatesResponseTransactionId()
    {
        QByteArray response(12, '\0');
        qToBigEndian<quint16>(0x1234, reinterpret_cast<uchar*>(response.data()));
        qToBigEndian<quint16>(0x8180, reinterpret_cast<uchar*>(response.data() + 2));

        QVERIFY(DnsPacket::isValidResponse(response, 0x1234));
        QVERIFY(!DnsPacket::isValidResponse(response, 0x4321));
    }

    void detectsAuthenticatedDataBit()
    {
        QByteArray response(12, '\0');
        qToBigEndian<quint16>(0x81a0, reinterpret_cast<uchar*>(response.data() + 2));

        QVERIFY(DnsPacket::authenticatedDataBit(response));

        qToBigEndian<quint16>(0x8180, reinterpret_cast<uchar*>(response.data() + 2));
        QVERIFY(!DnsPacket::authenticatedDataBit(response));
    }
};

QTEST_GUILESS_MAIN(DnsPacketTest)
#include "test_dns_packet.moc"
