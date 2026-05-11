#include "cli/HeadlessBenchmark.h"
#include "ui/MainWindow.h"

#include <QApplication>
#include <QByteArray>
#include <QCoreApplication>
#include <QIcon>

namespace {

bool headlessRequested(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i) {
        if (QString::fromLocal8Bit(argv[i]) == QLatin1String("--headless")) {
            return true;
        }
    }
    return false;
}

void suppressRecoveredQtNetworkNoise()
{
    QByteArray rules = qgetenv("QT_LOGGING_RULES");
    if (!rules.isEmpty() && !rules.endsWith('\n') && !rules.endsWith(';')) {
        rules.append('\n');
    }
    rules.append("qt.network.http2.debug=false\n");
    rules.append("qt.network.http2.info=false\n");
    rules.append("qt.network.http2.warning=false\n");
    qputenv("QT_LOGGING_RULES", rules);
}

void configureApplication()
{
    QCoreApplication::setOrganizationName(QStringLiteral("dnsbench"));
    QCoreApplication::setApplicationName(QStringLiteral("DNS Benchmark"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

    qRegisterMetaType<Statistics>("Statistics");
    qRegisterMetaType<ResolverStatus>("ResolverStatus");
    qRegisterMetaType<QVector<ResolverSamplePoint>>("QVector<ResolverSamplePoint>");
}

}

int main(int argc, char* argv[])
{
    suppressRecoveredQtNetworkNoise();

    if (headlessRequested(argc, argv)) {
        QCoreApplication app(argc, argv);
        configureApplication();
        return runHeadlessBenchmark(app);
    }

    QApplication app(argc, argv);
    configureApplication();
    app.setWindowIcon(QIcon(QStringLiteral(":/dnsbench.svg")));

    MainWindow window;
    window.show();
    return app.exec();
}
