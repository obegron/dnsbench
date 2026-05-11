#include "benchmark/BenchmarkController.h"
#include "benchmark/UdpResolver.h"

#include <QEventLoop>
#include <QHostAddress>
#include <QTest>
#include <QTimer>
#include <QUdpSocket>
#include <QtEndian>

#include <optional>

namespace {

void appendUInt16(QByteArray& out, quint16 value)
{
    const quint16 be = qToBigEndian(value);
    out.append(reinterpret_cast<const char*>(&be), sizeof(be));
}

void appendUInt32(QByteArray& out, quint32 value)
{
    const quint32 be = qToBigEndian(value);
    out.append(reinterpret_cast<const char*>(&be), sizeof(be));
}

QByteArray responseForQuery(const QByteArray& query, std::optional<quint16> idOverride = std::nullopt)
{
    if (query.size() < 16) {
        return {};
    }

    int questionEnd = 12;
    while (questionEnd < query.size() && query.at(questionEnd) != '\0') {
        const quint8 labelLength = static_cast<quint8>(query.at(questionEnd));
        if ((labelLength & 0xc0) != 0 || labelLength == 0 || questionEnd + 1 + labelLength >= query.size()) {
            return {};
        }
        questionEnd += 1 + labelLength;
    }
    questionEnd += 1 + 4; // root label, QTYPE, QCLASS
    if (questionEnd > query.size()) {
        return {};
    }

    const quint16 requestId = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(query.constData()));

    QByteArray response;
    appendUInt16(response, idOverride.value_or(requestId));
    appendUInt16(response, 0x8180); // response, recursion desired/available, no error
    appendUInt16(response, 1);      // QDCOUNT
    appendUInt16(response, 1);      // ANCOUNT
    appendUInt16(response, 0);      // NSCOUNT
    appendUInt16(response, 0);      // ARCOUNT
    response.append(query.constData() + 12, questionEnd - 12);

    appendUInt16(response, 0xc00c); // compressed answer name pointing at QNAME
    appendUInt16(response, 1);      // A
    appendUInt16(response, 1);      // IN
    appendUInt32(response, 60);     // TTL
    appendUInt16(response, 4);      // RDLENGTH
    response.append(QByteArray::fromHex("cb00710a")); // 203.0.113.10
    return response;
}

class LocalUdpDnsServer final : public QObject {
public:
    explicit LocalUdpDnsServer(QObject* parent = nullptr)
        : QObject(parent)
    {
        connect(&m_socket, &QUdpSocket::readyRead, this, [this]() {
            handleReadyRead();
        });
    }

    bool bind()
    {
        return m_socket.bind(QHostAddress::LocalHost, 0);
    }

    quint16 port() const
    {
        return m_socket.localPort();
    }

    QString errorString() const
    {
        return m_socket.errorString();
    }

    int requestCount() const
    {
        return m_requestCount;
    }

    void setDropResponses(bool dropResponses)
    {
        m_dropResponses = dropResponses;
    }

    void setSendWrongIdBeforeValidResponse(bool enabled)
    {
        m_sendWrongIdBeforeValidResponse = enabled;
    }

private:
    QUdpSocket m_socket;
    int m_requestCount = 0;
    bool m_dropResponses = false;
    bool m_sendWrongIdBeforeValidResponse = false;

    void handleReadyRead()
    {
        while (m_socket.hasPendingDatagrams()) {
            QByteArray datagram;
            datagram.resize(static_cast<int>(m_socket.pendingDatagramSize()));
            QHostAddress sender;
            quint16 senderPort = 0;
            m_socket.readDatagram(datagram.data(), datagram.size(), &sender, &senderPort);
            ++m_requestCount;

            if (m_dropResponses) {
                continue;
            }

            if (m_sendWrongIdBeforeValidResponse) {
                if (datagram.size() < 2) {
                    continue;
                }
                const quint16 requestId = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(datagram.constData()));
                const QByteArray wrongIdResponse = responseForQuery(datagram, requestId ^ 0x00ff);
                m_socket.writeDatagram(wrongIdResponse, sender, senderPort);
            }

            const QByteArray response = responseForQuery(datagram);
            QTimer::singleShot(m_sendWrongIdBeforeValidResponse ? 10 : 0, &m_socket, [this, response, sender, senderPort]() {
                m_socket.writeDatagram(response, sender, senderPort);
            });
        }
    }
};

ResolverEntry localResolverEntry(quint16 port)
{
    ResolverEntry entry;
    entry.id = QStringLiteral("local-udp");
    entry.address = QStringLiteral("127.0.0.1");
    entry.port = port;
    entry.protocol = ResolverProtocol::IPv4;
    entry.displayName = QStringLiteral("Local UDP");
    return entry;
}

}

class UdpBenchmarkTest : public QObject {
    Q_OBJECT

private slots:
    void udpResolverSucceedsAgainstLocalServer()
    {
        LocalUdpDnsServer server;
        QVERIFY2(server.bind(), qPrintable(server.errorString()));

        UdpResolver resolver(localResolverEntry(server.port()), 1000);

        QEventLoop loop;
        bool called = false;
        bool success = false;
        qint64 rttMs = -1;
        resolver.query(QStringLiteral("example.com"), [&](qint64 measuredRttMs, bool measuredSuccess) {
            called = true;
            success = measuredSuccess;
            rttMs = measuredRttMs;
            loop.quit();
        });
        QTimer::singleShot(1500, &loop, &QEventLoop::quit);
        loop.exec();

        QVERIFY(called);
        QVERIFY2(success, qPrintable(resolver.lastErrorString()));
        QVERIFY(rttMs >= 0);
        QCOMPARE(server.requestCount(), 1);
    }

    void udpResolverIgnoresMismatchedTransactionId()
    {
        LocalUdpDnsServer server;
        server.setSendWrongIdBeforeValidResponse(true);
        QVERIFY2(server.bind(), qPrintable(server.errorString()));

        UdpResolver resolver(localResolverEntry(server.port()), 1000);

        QEventLoop loop;
        bool called = false;
        bool success = false;
        resolver.query(QStringLiteral("example.com"), [&](qint64, bool measuredSuccess) {
            called = true;
            success = measuredSuccess;
            loop.quit();
        });
        QTimer::singleShot(1500, &loop, &QEventLoop::quit);
        loop.exec();

        QVERIFY(called);
        QVERIFY2(success, qPrintable(resolver.lastErrorString()));
        QCOMPARE(server.requestCount(), 1);
    }

    void udpResolverReportsTimeout()
    {
        LocalUdpDnsServer server;
        server.setDropResponses(true);
        QVERIFY2(server.bind(), qPrintable(server.errorString()));

        UdpResolver resolver(localResolverEntry(server.port()), 50);

        QEventLoop loop;
        bool called = false;
        bool success = true;
        resolver.query(QStringLiteral("example.com"), [&](qint64, bool measuredSuccess) {
            called = true;
            success = measuredSuccess;
            loop.quit();
        });
        QTimer::singleShot(1000, &loop, &QEventLoop::quit);
        loop.exec();

        QVERIFY(called);
        QVERIFY(!success);
        QVERIFY(resolver.lastErrorString().contains(QStringLiteral("timeout")));
        QCOMPARE(server.requestCount(), 1);
    }

    void benchmarkControllerAggregatesUdpSamples()
    {
        LocalUdpDnsServer server;
        QVERIFY2(server.bind(), qPrintable(server.errorString()));

        BenchmarkController controller;
        controller.setMaxConcurrentResolvers(1);

        QEventLoop loop;
        bool benchmarkFinished = false;
        bool resolverFinished = false;
        Statistics stats;
        ResolverStatus status = ResolverStatus::Idle;
        QVector<ResolverSamplePoint> samples;

        connect(&controller, &BenchmarkController::resolverFinished, this,
            [&](const QString& resolverId, const Statistics& emittedStats, ResolverStatus emittedStatus, bool, const QVector<ResolverSamplePoint>& emittedSamples) {
                QCOMPARE(resolverId, QStringLiteral("local-udp"));
                resolverFinished = true;
                stats = emittedStats;
                status = emittedStatus;
                samples = emittedSamples;
            });
        connect(&controller, &BenchmarkController::benchmarkFinished, this, [&]() {
            benchmarkFinished = true;
            loop.quit();
        });

        controller.start({localResolverEntry(server.port())}, 3, 0, {QStringLiteral("example.com")});
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        loop.exec();

        QVERIFY(benchmarkFinished);
        QVERIFY(resolverFinished);
        QCOMPARE(status, ResolverStatus::Finished);
        QCOMPARE(stats.successCount, 3);
        QCOMPARE(stats.lossCount, 0);
        QCOMPARE(stats.totalCount, 3);
        QCOMPARE(samples.size(), 3);
        for (const ResolverSamplePoint& sample : samples) {
            QVERIFY(sample.success);
        }
        QCOMPARE(server.requestCount(), 4);
        QVERIFY(!controller.isRunning());
    }
};

QTEST_GUILESS_MAIN(UdpBenchmarkTest)
#include "test_udp_benchmark.moc"
