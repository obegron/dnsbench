#include "cli/HeadlessBenchmark.h"
#include "ui/MainWindow.h"

#include <QApplication>
#include <QByteArray>
#include <QCoreApplication>
#include <QIcon>
#include <QStyleFactory>

#if defined(Q_OS_WIN)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

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
    // Qt reads logging rules during application startup; set these before
    // QCoreApplication exists so recovered HTTP/2 stream noise stays hidden.
    QByteArray rules = qgetenv("QT_LOGGING_RULES");
    if (!rules.isEmpty() && !rules.endsWith(';')) {
        rules.append(';');
    }
    rules.append("qt.network.http2.debug=false;");
    rules.append("qt.network.http2.info=false;");
    rules.append("qt.network.http2.warning=false");
    qputenv("QT_LOGGING_RULES", rules);
}

void preferSoftwareRendering()
{
    // Wine/DXVK can make Qt's first QWidget paint path slow or noisy. Prefer
    // the software backend unless the caller has explicitly selected one.
    if (qEnvironmentVariableIsEmpty("QT_OPENGL")) {
        qputenv("QT_OPENGL", "software");
    }
#if defined(Q_OS_WIN)
    if (qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) {
        qputenv("QT_QPA_PLATFORM", "windows:fontengine=freetype");
    }
#endif
    QCoreApplication::setAttribute(Qt::AA_UseSoftwareOpenGL);
}

void configureApplication()
{
    QCoreApplication::setOrganizationName(QStringLiteral("dnsbench"));
    QCoreApplication::setApplicationName(QStringLiteral("DNS Benchmark"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.4"));

    qRegisterMetaType<Statistics>("Statistics");
    qRegisterMetaType<ResolverStatus>("ResolverStatus");
    qRegisterMetaType<QVector<ResolverSamplePoint>>("QVector<ResolverSamplePoint>");
}

void configureWidgetStyle(QApplication& app)
{
#if defined(Q_OS_WIN)
    // Wine's native Windows style can be slow and visually inconsistent during
    // the first paint. Fusion is Qt-rendered and still available on real Windows.
    if (qEnvironmentVariableIsEmpty("DNSBENCH_QT_STYLE")) {
        app.setStyle(QStyleFactory::create(QStringLiteral("Fusion")));
    }
#else
    Q_UNUSED(app);
#endif
}

}

int main(int argc, char* argv[])
{
    suppressRecoveredQtNetworkNoise();
    preferSoftwareRendering();

    if (headlessRequested(argc, argv)) {
        QCoreApplication app(argc, argv);
        configureApplication();
        return runHeadlessBenchmark(app);
    }

    QApplication app(argc, argv);
    configureApplication();
    configureWidgetStyle(app);
    app.setWindowIcon(QIcon(QStringLiteral(":/dnsbench.svg")));

    auto* window = new MainWindow;
    window->show();
    const int exitCode = app.exec();
    window->prepareForExit();
#if defined(Q_OS_WIN)
    TerminateProcess(GetCurrentProcess(), static_cast<UINT>(exitCode));
#else
    delete window;
    return exitCode;
#endif
}
