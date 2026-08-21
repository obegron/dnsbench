#include <QCoreApplication>
#include <QProcess>
#include <QTest>

class HeadlessCliTest : public QObject {
    Q_OBJECT

private:
    struct ProcessResult {
        QProcess::ExitStatus exitStatus = QProcess::NormalExit;
        int exitCode = -1;
        QByteArray standardOutput;
        QByteArray standardError;
    };

    static ProcessResult run(const QStringList& arguments)
    {
        QProcess process;
        QString program = QCoreApplication::applicationDirPath() + QStringLiteral("/dnsbench");
#if defined(Q_OS_WIN)
        program += QStringLiteral(".exe");
#endif
        process.setProgram(program);
        process.setArguments(arguments);
        process.start();
        if (!process.waitForFinished(10000)) {
            process.kill();
            process.waitForFinished();
        }
        return {process.exitStatus(), process.exitCode(), process.readAllStandardOutput(), process.readAllStandardError()};
    }

private slots:
    void exposesUncachedWithoutMisleadingConcurrencyOption()
    {
        const ProcessResult process = run({QStringLiteral("--headless"), QStringLiteral("--help")});
        QCOMPARE(process.exitStatus, QProcess::NormalExit);
        QCOMPARE(process.exitCode, 0);
        const QByteArray output = process.standardOutput;
        QVERIFY(output.contains("--uncached"));
        QVERIFY(!output.contains("--concurrent"));
    }

    void rejectsInvalidArguments()
    {
        const ProcessResult process = run({
            QStringLiteral("--headless"),
            QStringLiteral("--resolver"),
            QStringLiteral("127.0.0.1"),
            QStringLiteral("--samples"),
            QStringLiteral("0"),
        });
        QCOMPARE(process.exitStatus, QProcess::NormalExit);
        QCOMPARE(process.exitCode, 2);
        QVERIFY(process.standardError.contains("--samples must be a positive integer"));
    }

    void reportsFailureWhenNoResolverProducesAResult()
    {
        const ProcessResult process = run({
            QStringLiteral("--headless"),
            QStringLiteral("--resolver"),
            QStringLiteral("not-an-ip,IPv4"),
            QStringLiteral("--samples"),
            QStringLiteral("1"),
            QStringLiteral("--delay"),
            QStringLiteral("0"),
            QStringLiteral("--domain-limit"),
            QStringLiteral("1"),
        });
        QCOMPARE(process.exitStatus, QProcess::NormalExit);
        QCOMPARE(process.exitCode, 1);
        const QByteArray output = process.standardOutput;
        QVERIFY(output.contains("| - | - | 100.0% | - | - | - |"));
    }
};

QTEST_GUILESS_MAIN(HeadlessCliTest)
#include "test_headless_cli.moc"
