#include "detection/LinuxDnsDetector.h"

#include <QTest>

class DnsDetectionTest : public QObject {
    Q_OBJECT

private slots:
    void parsesResolvConfNameservers()
    {
        const QByteArray content =
            "# generated\n"
            "nameserver 192.168.1.1\n"
            "nameserver   2001:4860:4860::8888  # google\n"
            "search lan\n"
            "; ignored\n"
            "nameserver invalid\n";

        const QList<ResolverEntry> entries = LinuxDnsDetector::parseResolvConf(content);
        QCOMPARE(entries.size(), 2);
        QCOMPARE(entries.at(0).address, QStringLiteral("192.168.1.1"));
        QCOMPARE(entries.at(0).protocol, ResolverProtocol::IPv4);
        QCOMPARE(entries.at(1).address, QStringLiteral("2001:4860:4860::8888"));
        QCOMPARE(entries.at(1).protocol, ResolverProtocol::IPv6);
    }

    void deduplicatesResolvConf()
    {
        const QByteArray content =
            "nameserver 1.1.1.1\n"
            "nameserver 1.1.1.1\n";

        const QList<ResolverEntry> entries = LinuxDnsDetector::parseResolvConf(content);
        QCOMPARE(entries.size(), 1);
    }

    void parsesResolvectlJsonRecursively()
    {
        const QByteArray content = R"json(
            {
              "Interfaces": [
                {
                  "DNS Servers": ["10.0.0.1", "2606:4700:4700::1111"],
                  "Domains": ["example.test"]
                }
              ]
            }
        )json";

        const QList<ResolverEntry> entries = LinuxDnsDetector::parseResolvectlJson(content);
        QCOMPARE(entries.size(), 2);
        QCOMPARE(entries.at(0).address, QStringLiteral("10.0.0.1"));
        QCOMPARE(entries.at(1).protocol, ResolverProtocol::IPv6);
    }
};

QTEST_GUILESS_MAIN(DnsDetectionTest)
#include "test_dns_detection.moc"
