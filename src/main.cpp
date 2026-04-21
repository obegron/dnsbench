#include "ui/MainWindow.h"

#include <QApplication>
#include <QCoreApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName(QStringLiteral("dnsbench"));
    QCoreApplication::setApplicationName(QStringLiteral("DNS Benchmark"));
    QCoreApplication::setApplicationVersion(QStringLiteral("0.1.0"));

    qRegisterMetaType<Statistics>("Statistics");
    qRegisterMetaType<ResolverStatus>("ResolverStatus");

    MainWindow window;
    window.show();
    return app.exec();
}
