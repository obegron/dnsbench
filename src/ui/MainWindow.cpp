#include "ui/MainWindow.h"

#include "detection/SystemDnsDetector.h"
#include "export/ResultExporter.h"
#include "ui/AddResolverDialog.h"
#include "ui/ResultsTab.h"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QFile>
#include <QFileDialog>
#include <QHeaderView>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSettings>
#include <QSet>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include <QTableView>
#include <QTextEdit>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <limits>

namespace {

class PinnedSortProxyModel : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

protected:
    bool lessThan(const QModelIndex& left, const QModelIndex& right) const override
    {
        const bool leftPinned = sourceModel()->index(left.row(), ResolverModel::PinColumn).data(Qt::UserRole).toBool();
        const bool rightPinned = sourceModel()->index(right.row(), ResolverModel::PinColumn).data(Qt::UserRole).toBool();
        if (leftPinned != rightPinned) {
            return leftPinned;
        }
        return QSortFilterProxyModel::lessThan(left, right);
    }
};

class LatencyBarDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        const QString status = index.sibling(index.row(), ResolverModel::StatusColumn).data(Qt::DisplayRole).toString();
        if (status != QLatin1String("Finished")) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        QStyleOptionViewItem itemOption(option);
        initStyleOption(&itemOption, index);
        itemOption.text.clear();
        QStyle* style = itemOption.widget ? itemOption.widget->style() : QApplication::style();
        style->drawControl(QStyle::CE_ItemViewItem, &itemOption, painter, itemOption.widget);

        const double median = index.data(Qt::UserRole).toDouble();
        const double loss = index.sibling(index.row(), ResolverModel::LossColumn).data(Qt::UserRole).toDouble();
        const double scaleMs = 100.0;
        const QRect bar = option.rect.adjusted(6, 7, -6, -7);
        const int fillWidth = std::max(2, static_cast<int>(bar.width() * std::min(median, scaleMs) / scaleMs));

        QColor fill(57, 154, 89);
        if (loss > 1.0 || median > 50.0) {
            fill = QColor(196, 69, 54);
        } else if (median > 20.0) {
            fill = QColor(210, 154, 45);
        }

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, false);
        painter->fillRect(bar, QColor(235, 238, 241));
        painter->fillRect(QRect(bar.left(), bar.top(), fillWidth, bar.height()), fill);
        painter->setPen(option.palette.text().color());
        painter->drawText(option.rect.adjusted(8, 0, -8, 0), Qt::AlignVCenter | Qt::AlignRight,
            QStringLiteral("%1 ms").arg(median, 0, 'f', 1));
        painter->restore();
    }
};

ResolverEntry publicResolver(const QString& name, const QString& address, ResolverProtocol protocol, int port = 53)
{
    ResolverEntry entry;
    entry.displayName = name;
    entry.address = address;
    entry.protocol = protocol;
    entry.port = port;
    entry.builtInResolver = true;
    entry.id = ResolverModel::makeId(entry);
    return entry;
}

QList<ResolverEntry> builtInResolvers()
{
    return {
        publicResolver(QStringLiteral("Cloudflare 1.1.1.1"), QStringLiteral("1.1.1.1"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Cloudflare 1.0.0.1"), QStringLiteral("1.0.0.1"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Cloudflare IPv6"), QStringLiteral("2606:4700:4700::1111"), ResolverProtocol::IPv6),
        publicResolver(QStringLiteral("Cloudflare DoH"), QStringLiteral("https://cloudflare-dns.com/dns-query"), ResolverProtocol::DoH),
        publicResolver(QStringLiteral("Cloudflare DoT"), QStringLiteral("1.1.1.1"), ResolverProtocol::DoT, 853),
        publicResolver(QStringLiteral("Google 8.8.8.8"), QStringLiteral("8.8.8.8"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Google 8.8.4.4"), QStringLiteral("8.8.4.4"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Google IPv6"), QStringLiteral("2001:4860:4860::8888"), ResolverProtocol::IPv6),
        publicResolver(QStringLiteral("Google DoH"), QStringLiteral("https://dns.google/dns-query"), ResolverProtocol::DoH),
        publicResolver(QStringLiteral("Google DoT"), QStringLiteral("8.8.8.8"), ResolverProtocol::DoT, 853),
        publicResolver(QStringLiteral("Quad9 9.9.9.9"), QStringLiteral("9.9.9.9"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Quad9 149.112.112.112"), QStringLiteral("149.112.112.112"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Quad9 IPv6"), QStringLiteral("2620:fe::fe"), ResolverProtocol::IPv6),
        publicResolver(QStringLiteral("Quad9 DoH"), QStringLiteral("https://dns.quad9.net/dns-query"), ResolverProtocol::DoH),
        publicResolver(QStringLiteral("Quad9 DoT"), QStringLiteral("9.9.9.9"), ResolverProtocol::DoT, 853),
        publicResolver(QStringLiteral("OpenDNS 208.67.222.222"), QStringLiteral("208.67.222.222"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("OpenDNS 208.67.220.220"), QStringLiteral("208.67.220.220"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("AdGuard 94.140.14.14"), QStringLiteral("94.140.14.14"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("AdGuard 94.140.15.15"), QStringLiteral("94.140.15.15"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("AdGuard DoH"), QStringLiteral("https://dns.adguard-dns.com/dns-query"), ResolverProtocol::DoH),
        publicResolver(QStringLiteral("AdGuard DoT"), QStringLiteral("94.140.14.14"), ResolverProtocol::DoT, 853),
        publicResolver(QStringLiteral("Control D 76.76.2.0"), QStringLiteral("76.76.2.0"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Control D 76.76.10.0"), QStringLiteral("76.76.10.0"), ResolverProtocol::IPv4),
        publicResolver(QStringLiteral("Control D DoH"), QStringLiteral("https://freedns.controld.com/p0"), ResolverProtocol::DoH),
    };
}

bool isBuiltInResolverName(const QString& displayName)
{
    static const QSet<QString> names = [] {
        QSet<QString> result;
        for (const ResolverEntry& entry : builtInResolvers()) {
            result.insert(entry.displayName);
        }
        return result;
    }();
    return names.contains(displayName);
}

}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    buildUi();
    connectController();
    loadSettings();
    detectSystemDns();
    addBuiltInResolvers();
}

MainWindow::~MainWindow()
{
    saveSettings();
}

void MainWindow::buildUi()
{
    setWindowTitle(QStringLiteral("DNS Benchmark"));
    resize(1200, 760);

    m_proxy = new PinnedSortProxyModel(this);
    m_proxy->setSourceModel(&m_model);
    m_proxy->setSortRole(Qt::UserRole);
    m_proxy->setDynamicSortFilter(true);

    m_table = new QTableView(this);
    m_table->setModel(m_proxy);
    m_table->setSortingEnabled(true);
    m_table->sortByColumn(ResolverModel::MedianColumn, Qt::AscendingOrder);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setAlternatingRowColors(true);
    m_table->setItemDelegateForColumn(ResolverModel::MedianColumn, new LatencyBarDelegate(m_table));

    m_resultsTab = new ResultsTab(this);
    m_conclusions = new QTextEdit(this);
    m_conclusions->setReadOnly(true);
    m_log = new QPlainTextEdit(this);
    m_log->setReadOnly(true);
    QFont monospace(QStringLiteral("monospace"));
    monospace.setStyleHint(QFont::Monospace);
    m_log->setFont(monospace);

    auto* tabs = new QTabWidget(this);
    tabs->addTab(m_resultsTab, QStringLiteral("Results"));
    tabs->addTab(m_conclusions, QStringLiteral("Conclusions"));
    tabs->addTab(m_log, QStringLiteral("Log"));

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(m_table);
    splitter->addWidget(tabs);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);

    auto* toolbar = addToolBar(QStringLiteral("Benchmark"));
    toolbar->setMovable(false);
    const QAction* startAction = toolbar->addAction(QStringLiteral("Start"), this, &MainWindow::startBenchmark);
    Q_UNUSED(startAction);
    toolbar->addAction(QStringLiteral("Stop"), this, &MainWindow::stopBenchmark);
    toolbar->addSeparator();
    toolbar->addAction(QStringLiteral("Add Resolver"), this, &MainWindow::addResolver);
    toolbar->addAction(QStringLiteral("Detect System DNS"), this, &MainWindow::detectSystemDns);
    toolbar->addAction(QStringLiteral("Export"), this, &MainWindow::exportResults);
    toolbar->addAction(QStringLiteral("Clone Results"), this, &MainWindow::cloneResults);
    toolbar->addSeparator();

    m_ipv4Toggle = new QCheckBox(QStringLiteral("IPv4"), this);
    m_ipv6Toggle = new QCheckBox(QStringLiteral("IPv6"), this);
    m_dohToggle = new QCheckBox(QStringLiteral("DoH"), this);
    m_dotToggle = new QCheckBox(QStringLiteral("DoT"), this);
    for (QCheckBox* box : {m_ipv4Toggle, m_ipv6Toggle, m_dohToggle, m_dotToggle}) {
        box->setChecked(true);
        toolbar->addWidget(box);
    }

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Samples"), this));
    m_sampleSpin = new QSpinBox(this);
    m_sampleSpin->setRange(1, 25000);
    m_sampleSpin->setValue(250);
    toolbar->addWidget(m_sampleSpin);

    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_etaLabel = new QLabel(QStringLiteral("0/0 queries | ETA: -"), this);
    statusBar()->addPermanentWidget(m_etaLabel);
    statusBar()->addPermanentWidget(m_progress, 1);

    auto* fileMenu = menuBar()->addMenu(QStringLiteral("File"));
    fileMenu->addAction(QStringLiteral("Export Results"), this, &MainWindow::exportResults);
    fileMenu->addSeparator();
    fileMenu->addAction(QStringLiteral("Quit"), this, &QWidget::close);

    auto* benchmarkMenu = menuBar()->addMenu(QStringLiteral("Benchmark"));
    benchmarkMenu->addAction(QStringLiteral("Start"), this, &MainWindow::startBenchmark);
    benchmarkMenu->addAction(QStringLiteral("Stop"), this, &MainWindow::stopBenchmark);
    benchmarkMenu->addAction(QStringLiteral("Clone Results"), this, &MainWindow::cloneResults);
}

void MainWindow::connectController()
{
    connect(&m_controller, &BenchmarkController::progressUpdated, this, &MainWindow::updateProgress);
    connect(&m_controller, &BenchmarkController::resolverFinished, this, [this](const QString& resolverId, const Statistics& stats, ResolverStatus status) {
        m_model.updateStats(resolverId, stats, status);
    });
    connect(&m_controller, &BenchmarkController::resolverStatusChanged, &m_model, &ResolverModel::updateStatus);
    connect(&m_controller, &BenchmarkController::logLine, this, &MainWindow::appendLogLine);
    connect(&m_controller, &BenchmarkController::benchmarkFinished, this, &MainWindow::updateConclusions);
}

void MainWindow::detectSystemDns()
{
    const std::unique_ptr<SystemDnsDetector> detector = createSystemDnsDetector();
    if (!detector) {
        appendLogLine(QStringLiteral("System DNS detection is not implemented for this platform yet."));
        return;
    }

    const QList<ResolverEntry> detected = detector->detect();
    for (const ResolverEntry& entry : detected) {
        if (!m_model.find(entry.id)) {
            m_model.addResolver(entry);
        }
    }
    appendLogLine(QStringLiteral("Detected %1 system DNS resolver(s).").arg(detected.size()));
}

void MainWindow::addBuiltInResolvers()
{
    int added = 0;
    for (const ResolverEntry& entry : builtInResolvers()) {
        if (!m_model.find(entry.id)) {
            m_model.addResolver(entry);
            ++added;
        }
    }
    appendLogLine(QStringLiteral("Added %1 built-in public resolver(s).").arg(added));
}

void MainWindow::addResolver()
{
    AddResolverDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted) {
        return;
    }

    const ResolverEntry entry = dialog.resolver();
    if (m_model.find(entry.id)) {
        QMessageBox::information(this, QStringLiteral("Resolver Exists"), QStringLiteral("That resolver is already in the list."));
        return;
    }
    m_model.addResolver(entry);
}

void MainWindow::startBenchmark()
{
    m_model.setProtocolEnabled(ResolverProtocol::IPv4, m_ipv4Toggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::IPv6, m_ipv6Toggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::DoH, m_dohToggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::DoT, m_dotToggle->isChecked());
    m_model.resetRuntimeState();
    m_progress->setValue(0);
    m_conclusions->clear();
    appendLogLine(QStringLiteral("Starting benchmark."));
    m_controller.start(m_model.enabledEntries(), m_sampleSpin->value(), loadDomains());
}

void MainWindow::stopBenchmark()
{
    m_controller.stop();
}

void MainWindow::exportResults()
{
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Export Results"), QStringLiteral("dnsbench-results.csv"), QStringLiteral("CSV (*.csv);;Text Table (*.txt)"));
    if (path.isEmpty()) {
        return;
    }

    QString error;
    const bool ok = path.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive)
        ? ResultExporter::saveTextTable(path, m_model.entries(), &error)
        : ResultExporter::saveCsv(path, m_model.entries(), &error);
    if (!ok) {
        QMessageBox::warning(this, QStringLiteral("Export Failed"), error);
    }
}

void MainWindow::cloneResults()
{
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("Cloned Results"));
    dialog->resize(1000, 500);

    auto* text = new QPlainTextEdit(ResultExporter::toTextTable(m_model.entries()), dialog);
    text->setReadOnly(true);
    QFont monospace(QStringLiteral("monospace"));
    monospace.setStyleHint(QFont::Monospace);
    text->setFont(monospace);

    auto* layout = new QVBoxLayout(dialog);
    layout->addWidget(text);
    dialog->show();
}

void MainWindow::appendLogLine(const QString& line)
{
    m_log->appendPlainText(QStringLiteral("[%1] %2").arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")), line));
}

void MainWindow::updateProgress(int completed, int total, qint64 elapsedMs)
{
    m_progress->setRange(0, total == 0 ? 1 : total);
    m_progress->setValue(completed);

    QString eta = QStringLiteral("-");
    if (completed > 0 && total > completed) {
        const qint64 etaMs = (elapsedMs / completed) * (total - completed);
        eta = QStringLiteral("%1s").arg((etaMs + 999) / 1000);
    }
    m_etaLabel->setText(QStringLiteral("%1/%2 queries | ETA: %3").arg(completed).arg(total).arg(eta));
}

void MainWindow::updateConclusions()
{
    const QList<ResolverEntry> entries = m_model.entries();
    QList<ResolverEntry> finished;
    QList<ResolverEntry> sidelined;
    ResolverEntry stable;
    ResolverEntry system;
    bool hasStable = false;
    bool hasSystem = false;
    QStringList unreliable;

    for (const ResolverEntry& entry : entries) {
        if (entry.status == ResolverStatus::Sidelined) {
            sidelined.push_back(entry);
            if (entry.systemResolver && !hasSystem) {
                system = entry;
                hasSystem = true;
            }
            continue;
        }
        if (entry.status != ResolverStatus::Finished || !entry.stats.hasSamples()) {
            continue;
        }
        finished.push_back(entry);
        if (!hasStable || entry.stats.stddevMs < stable.stats.stddevMs) {
            stable = entry;
            hasStable = true;
        }
        if (entry.systemResolver && !hasSystem) {
            system = entry;
            hasSystem = true;
        }
        if (entry.stats.lossPercent > 1.0) {
            unreliable.push_back(QStringLiteral("%1 (%2% loss)").arg(entry.effectiveName()).arg(entry.stats.lossPercent, 0, 'f', 1));
        }
    }

    std::sort(finished.begin(), finished.end(), [](const ResolverEntry& left, const ResolverEntry& right) {
        if (left.stats.medianMs == right.stats.medianMs) {
            return left.stats.meanMs < right.stats.meanMs;
        }
        return left.stats.medianMs < right.stats.medianMs;
    });

    QStringList lines;
    if (!finished.isEmpty()) {
        const ResolverEntry& fastest = finished.first();
        lines << QStringLiteral("Fastest resolver: %1, median %2 ms, mean %3 ms.")
                     .arg(fastest.effectiveName())
                     .arg(fastest.stats.medianMs, 0, 'f', 1)
                     .arg(fastest.stats.meanMs, 0, 'f', 1);
    }
    if (hasStable) {
        lines << QStringLiteral("Most stable resolver: %1, stddev %2 ms.").arg(stable.effectiveName()).arg(stable.stats.stddevMs, 0, 'f', 1);
    }
    if (!unreliable.isEmpty()) {
        lines << QStringLiteral("Resolvers with >1% loss: %1.").arg(unreliable.join(QStringLiteral(", ")));
    }
    if (hasSystem && system.status == ResolverStatus::Finished && !finished.isEmpty()) {
        const ResolverEntry& fastest = finished.first();
        if (system.id == fastest.id) {
            lines << QStringLiteral("System DNS is the fastest measured resolver.");
        } else {
            lines << QStringLiteral("System DNS is %1 ms slower than the fastest alternative.")
                         .arg(system.stats.medianMs - fastest.stats.medianMs, 0, 'f', 1);
        }
    } else if (hasSystem && system.status == ResolverStatus::Sidelined) {
        lines << QStringLiteral("System DNS was sidelined during warm-up; it did not answer at least 3 of 10 reachability probes.");
    }

    if (!finished.isEmpty()) {
        QStringList top;
        const int topCount = std::min(5, static_cast<int>(finished.size()));
        for (int i = 0; i < topCount; ++i) {
            const ResolverEntry& entry = finished.at(i);
            top << QStringLiteral("%1. %2: median %3 ms, mean %4 ms")
                       .arg(i + 1)
                       .arg(entry.effectiveName())
                       .arg(entry.stats.medianMs, 0, 'f', 1)
                       .arg(entry.stats.meanMs, 0, 'f', 1);
        }
        lines << QStringLiteral("Top performers:\n%1").arg(top.join(QStringLiteral("\n")));
    }

    if (!sidelined.isEmpty()) {
        int ipv6 = 0;
        int doh = 0;
        int dot = 0;
        int udp = 0;
        for (const ResolverEntry& entry : sidelined) {
            switch (entry.protocol) {
            case ResolverProtocol::IPv6:
                ++ipv6;
                break;
            case ResolverProtocol::DoH:
                ++doh;
                break;
            case ResolverProtocol::DoT:
                ++dot;
                break;
            case ResolverProtocol::IPv4:
                ++udp;
                break;
            }
        }
        lines << QStringLiteral("Sidelined: %1 total (%2 IPv4, %3 IPv6, %4 DoH, %5 DoT).")
                     .arg(sidelined.size())
                     .arg(udp)
                     .arg(ipv6)
                     .arg(doh)
                     .arg(dot);
    }

    const QString summary = lines.isEmpty() ? QStringLiteral("No completed resolver results.") : lines.join(QStringLiteral("\n"));
    m_conclusions->setPlainText(summary);
    m_resultsTab->setSummary(summary);
}

void MainWindow::loadSettings()
{
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
    m_sampleSpin->setValue(settings.value(QStringLiteral("benchmark/sampleCount"), 250).toInt());
    m_ipv4Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv4"), true).toBool());
    m_ipv6Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv6"), true).toBool());
    m_dohToggle->setChecked(settings.value(QStringLiteral("protocols/doh"), true).toBool());
    m_dotToggle->setChecked(settings.value(QStringLiteral("protocols/dot"), true).toBool());

    const int count = settings.beginReadArray(QStringLiteral("resolvers"));
    for (int i = 0; i < count; ++i) {
        settings.setArrayIndex(i);
        bool ok = false;
        ResolverEntry entry;
        entry.displayName = settings.value(QStringLiteral("displayName")).toString();
        entry.address = settings.value(QStringLiteral("address")).toString();
        entry.protocol = protocolFromString(settings.value(QStringLiteral("protocol")).toString(), &ok);
        entry.port = settings.value(QStringLiteral("port"), defaultPortForProtocol(entry.protocol)).toInt();
        entry.pinned = settings.value(QStringLiteral("pinned"), false).toBool();
        entry.enabled = settings.value(QStringLiteral("enabled"), true).toBool();
        if (isBuiltInResolverName(entry.displayName)) {
            continue;
        }
        if (ok && !entry.address.isEmpty()) {
            entry.id = ResolverModel::makeId(entry);
            m_model.addResolver(entry);
        }
    }
    settings.endArray();
}

void MainWindow::saveSettings()
{
    QSettings settings;
    settings.setValue(QStringLiteral("window/geometry"), saveGeometry());
    settings.setValue(QStringLiteral("benchmark/sampleCount"), m_sampleSpin->value());
    settings.setValue(QStringLiteral("protocols/ipv4"), m_ipv4Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/ipv6"), m_ipv6Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/doh"), m_dohToggle->isChecked());
    settings.setValue(QStringLiteral("protocols/dot"), m_dotToggle->isChecked());

    const QList<ResolverEntry> entries = m_model.entries();
    settings.beginWriteArray(QStringLiteral("resolvers"));
    int index = 0;
    for (const ResolverEntry& entry : entries) {
        if (entry.systemResolver || entry.builtInResolver) {
            continue;
        }
        settings.setArrayIndex(index++);
        settings.setValue(QStringLiteral("displayName"), entry.displayName);
        settings.setValue(QStringLiteral("address"), entry.address);
        settings.setValue(QStringLiteral("protocol"), protocolToString(entry.protocol));
        settings.setValue(QStringLiteral("port"), entry.port);
        settings.setValue(QStringLiteral("pinned"), entry.pinned);
        settings.setValue(QStringLiteral("enabled"), entry.enabled);
    }
    settings.endArray();
}

QStringList MainWindow::loadDomains() const
{
    QFile file(QStringLiteral(":/test_domains.txt"));
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        return {};
    }

    QStringList domains;
    while (!file.atEnd()) {
        const QString line = QString::fromUtf8(file.readLine()).trimmed();
        if (!line.isEmpty() && !line.startsWith(QLatin1Char('#'))) {
            domains.push_back(line);
        }
    }
    return domains;
}
