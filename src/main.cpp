#include "ui/MainWindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QIcon>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("dnsbench"));
    QCoreApplication::setApplicationName(QStringLiteral("DNS Benchmark"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));
    app.setWindowIcon(QIcon(QStringLiteral(":/dnsbench.svg")));

    qRegisterMetaType<Statistics>("Statistics");
    qRegisterMetaType<ResolverStatus>("ResolverStatus");
    qRegisterMetaType<QVector<ResolverSamplePoint>>("QVector<ResolverSamplePoint>");

    MainWindow window;
    window.show();
    return app.exec();
}
