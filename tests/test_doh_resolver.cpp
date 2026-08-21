#include "benchmark/DohResolver.h"

#include <QTest>

namespace {

ResolverEntry dohEntry(const QString& address, int port)
{
    ResolverEntry entry;
    entry.id = QStringLiteral("test-doh");
    entry.address = address;
    entry.port = port;
    entry.protocol = ResolverProtocol::DoH;
    return entry;
}

}

class DohResolverTest : public QObject {
    Q_OBJECT

private slots:
    void appliesConfiguredPortWhenUrlHasNone()
    {
        DohResolver resolver(dohEntry(QStringLiteral("dns.example"), 8443));
        const QUrl endpoint = resolver.endpoint();

        QCOMPARE(endpoint.scheme(), QStringLiteral("https"));
        QCOMPARE(endpoint.host(), QStringLiteral("dns.example"));
        QCOMPARE(endpoint.port(), 8443);
        QCOMPARE(endpoint.path(), QStringLiteral("/dns-query"));
    }

    void preservesExplicitUrlPort()
    {
        DohResolver resolver(dohEntry(QStringLiteral("https://dns.example:9443/custom"), 8443));
        QCOMPARE(resolver.endpoint().port(), 9443);
        QCOMPARE(resolver.endpoint().path(), QStringLiteral("/custom"));
    }

    void rejectsNonHttpsEndpoint()
    {
        DohResolver resolver(dohEntry(QStringLiteral("http://dns.example/dns-query"), 80));
        QVERIFY(resolver.endpoint().isEmpty());

        bool called = false;
        bool success = true;
        resolver.query(QStringLiteral("example.com"), [&](qint64, bool querySuccess) {
            called = true;
            success = querySuccess;
        });
        QVERIFY(called);
        QVERIFY(!success);
        QVERIFY(resolver.lastErrorString().contains(QStringLiteral("HTTPS")));
    }
};

QTEST_GUILESS_MAIN(DohResolverTest)
#include "test_doh_resolver.moc"
