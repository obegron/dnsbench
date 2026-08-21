#include "ui/MainWindow.h"

#include "benchmark/PassAggregation.h"
#include "detection/SystemDnsDetector.h"
#include "export/ResultExporter.h"
#include "ui/AddResolverDialog.h"
#include "ui/ResultsTab.h"
#include "ui/TimelineChart.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCheckBox>
#include <QDateTime>
#include <QDialog>
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QLabel>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QSet>
#include <QSignalBlocker>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStandardPaths>
#include <QStatusBar>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QTabWidget>
#include <QTableView>
#include <QTextBrowser>
#include <QTextDocument>
#include <QTextStream>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>
#include <QTemporaryFile>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>

namespace {

constexpr int renderedMarkdownRowLimit = 250;
constexpr int maxModelUpdatesPerFlush = 50;
constexpr int browserImportDefaultLimit = 100;
constexpr int browserImportLookbackDays = 30;

enum class ResultFilter {
    All = 0,
    ReliableOnly = 1,
    UnreliableOnly = 2,
    NoResultOnly = 3
};

struct BrowserHistorySource {
    QString browserName;
    QString profileName;
    QString historyPath;

    QString label() const
    {
        return QStringLiteral("%1 - %2").arg(browserName, profileName);
    }
};

class ToolbarMenuButton final : public QToolButton {
public:
    explicit ToolbarMenuButton(QWidget* parent = nullptr)
        : QToolButton(parent)
    {
        setProperty("toolbarMenu", true);
    }

protected:
    void paintEvent(QPaintEvent* event) override
    {
        QToolButton::paintEvent(event);

        const QPalette::ColorGroup group = isEnabled() ? QPalette::Active : QPalette::Disabled;
        const QPalette::ColorRole role = isDown() ? QPalette::HighlightedText : QPalette::WindowText;
        QColor color = palette().color(group, role);
        color.setAlphaF(isEnabled() ? 0.85 : 0.45);

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing);
        QPen pen(color, 1.5, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin);
        painter.setPen(pen);

        const qreal centerX = width() - 9.0;
        const qreal centerY = height() / 2.0;
        QPainterPath chevron;
        chevron.moveTo(centerX - 3.0, centerY - 1.5);
        chevron.lineTo(centerX, centerY + 1.5);
        chevron.lineTo(centerX + 3.0, centerY - 1.5);
        painter.drawPath(chevron);
    }
};

struct BrowserDomainStats {
    QString domain;
    int visits = 0;
    int typed = 0;
    qint64 lastVisitTime = 0;
};

void addChromiumHistorySources(QList<BrowserHistorySource>* sources, const QString& browserName, const QString& userDataRoot)
{
    const QDir root(userDataRoot);
    if (!root.exists()) {
        return;
    }

    auto addProfile = [&](const QString& profileName, const QString& historyPath) {
        if (!QFileInfo::exists(historyPath)) {
            return;
        }
        if (profileName == QLatin1String("System Profile")) {
            return;
        }
        sources->push_back(BrowserHistorySource{browserName, profileName, historyPath});
    };

    addProfile(QStringLiteral("Default"), root.filePath(QStringLiteral("History")));
    const QFileInfoList profileDirs = root.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot | QDir::Readable);
    for (const QFileInfo& profileDir : profileDirs) {
        const QString profileName = profileDir.fileName();
        addProfile(profileName, QDir(profileDir.absoluteFilePath()).filePath(QStringLiteral("History")));
    }
}

QList<BrowserHistorySource> browserHistorySources()
{
    QList<BrowserHistorySource> sources;
    const QString home = QStandardPaths::writableLocation(QStandardPaths::HomeLocation);
#if defined(Q_OS_WIN)
    const QString localBase = QString::fromLocal8Bit(qgetenv("LOCALAPPDATA"));
    const QString roamingBase = QString::fromLocal8Bit(qgetenv("APPDATA"));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome"), QDir(localBase).filePath(QStringLiteral("Google/Chrome/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Beta"), QDir(localBase).filePath(QStringLiteral("Google/Chrome Beta/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Dev"), QDir(localBase).filePath(QStringLiteral("Google/Chrome Dev/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Chromium"), QDir(localBase).filePath(QStringLiteral("Chromium/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave"), QDir(localBase).filePath(QStringLiteral("BraveSoftware/Brave-Browser/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave Nightly"), QDir(localBase).filePath(QStringLiteral("BraveSoftware/Brave-Browser-Nightly/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge"), QDir(localBase).filePath(QStringLiteral("Microsoft/Edge/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Beta"), QDir(localBase).filePath(QStringLiteral("Microsoft/Edge Beta/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Dev"), QDir(localBase).filePath(QStringLiteral("Microsoft/Edge Dev/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Vivaldi"), QDir(localBase).filePath(QStringLiteral("Vivaldi/User Data")));
    addChromiumHistorySources(&sources, QStringLiteral("Opera"), QDir(roamingBase).filePath(QStringLiteral("Opera Software/Opera Stable")));
#elif defined(Q_OS_MACOS)
    const QDir appSupport(QDir(home).filePath(QStringLiteral("Library/Application Support")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome"), appSupport.filePath(QStringLiteral("Google/Chrome")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Beta"), appSupport.filePath(QStringLiteral("Google/Chrome Beta")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Dev"), appSupport.filePath(QStringLiteral("Google/Chrome Dev")));
    addChromiumHistorySources(&sources, QStringLiteral("Chromium"), appSupport.filePath(QStringLiteral("Chromium")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave"), appSupport.filePath(QStringLiteral("BraveSoftware/Brave-Browser")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave Nightly"), appSupport.filePath(QStringLiteral("BraveSoftware/Brave-Browser-Nightly")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge"), appSupport.filePath(QStringLiteral("Microsoft Edge")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Beta"), appSupport.filePath(QStringLiteral("Microsoft Edge Beta")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Dev"), appSupport.filePath(QStringLiteral("Microsoft Edge Dev")));
    addChromiumHistorySources(&sources, QStringLiteral("Vivaldi"), appSupport.filePath(QStringLiteral("Vivaldi")));
    addChromiumHistorySources(&sources, QStringLiteral("Opera"), appSupport.filePath(QStringLiteral("com.operasoftware.Opera")));
#else
    const QDir config(QDir(home).filePath(QStringLiteral(".config")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome"), config.filePath(QStringLiteral("google-chrome")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Beta"), config.filePath(QStringLiteral("google-chrome-beta")));
    addChromiumHistorySources(&sources, QStringLiteral("Chrome Unstable"), config.filePath(QStringLiteral("google-chrome-unstable")));
    addChromiumHistorySources(&sources, QStringLiteral("Chromium"), config.filePath(QStringLiteral("chromium")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave"), config.filePath(QStringLiteral("BraveSoftware/Brave-Browser")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave Nightly"), config.filePath(QStringLiteral("BraveSoftware/Brave-Browser-Nightly")));
    addChromiumHistorySources(&sources, QStringLiteral("Brave Origin Nightly"), config.filePath(QStringLiteral("BraveSoftware/Brave-Origin-Nightly")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge"), config.filePath(QStringLiteral("microsoft-edge")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Beta"), config.filePath(QStringLiteral("microsoft-edge-beta")));
    addChromiumHistorySources(&sources, QStringLiteral("Edge Dev"), config.filePath(QStringLiteral("microsoft-edge-dev")));
    addChromiumHistorySources(&sources, QStringLiteral("Vivaldi"), config.filePath(QStringLiteral("vivaldi")));
    addChromiumHistorySources(&sources, QStringLiteral("Opera"), config.filePath(QStringLiteral("opera")));
    addChromiumHistorySources(&sources, QStringLiteral("Chromium Snap"), QDir(home).filePath(QStringLiteral("snap/chromium/common/chromium")));
#endif

    std::sort(sources.begin(), sources.end(), [](const BrowserHistorySource& left, const BrowserHistorySource& right) {
        const int browserCompare = QString::localeAwareCompare(left.browserName, right.browserName);
        if (browserCompare != 0) {
            return browserCompare < 0;
        }
        return QString::localeAwareCompare(left.profileName, right.profileName) < 0;
    });
    return sources;
}

QString normalizedBrowserDomain(const QString& urlText)
{
    const QUrl url(urlText);
    QString host = url.host(QUrl::FullyDecoded).trimmed().toLower();
    while (host.endsWith(QLatin1Char('.'))) {
        host.chop(1);
    }
    if (host.startsWith(QStringLiteral("www."))) {
        host = host.mid(4);
    }

    QHostAddress address;
    if (host.isEmpty() || !host.contains(QLatin1Char('.')) || address.setAddress(host)) {
        return {};
    }
    return host;
}

QStringList domainsFromChromiumHistory(const QString& historyPath, int limit, int lookbackDays, QString* error)
{
    QTemporaryFile copy(QDir::tempPath() + QStringLiteral("/dnsbench-browser-history-XXXXXX.sqlite"));
    copy.setAutoRemove(true);
    if (!copy.open()) {
        if (error) {
            *error = copy.errorString();
        }
        return {};
    }
    const QString copyPath = copy.fileName();
    copy.close();
    QFile::remove(copyPath);
    if (!QFile::copy(historyPath, copyPath)) {
        if (error) {
            *error = QStringLiteral("Could not copy browser history database. Close the browser and try again if the profile is locked.");
        }
        return {};
    }

    const QString connectionName = QStringLiteral("browser-history-%1").arg(reinterpret_cast<quintptr>(&copy));
    QStringList result;
    {
        QSqlDatabase db = QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
        db.setDatabaseName(copyPath);
        if (!db.open()) {
            if (error) {
                *error = db.lastError().text();
            }
            db = {};
            QSqlDatabase::removeDatabase(connectionName);
            return {};
        }

        const qint64 chromeEpochDeltaSeconds = 11644473600LL;
        const qint64 cutoff = (QDateTime::currentDateTimeUtc().addDays(-lookbackDays).toSecsSinceEpoch() + chromeEpochDeltaSeconds) * 1000000LL;

        QSqlQuery query(db);
        query.prepare(QStringLiteral(
            "SELECT url, visit_count, typed_count, last_visit_time "
            "FROM urls "
            "WHERE last_visit_time >= ? "
            "ORDER BY visit_count DESC, typed_count DESC, last_visit_time DESC "
            "LIMIT 5000"));
        query.addBindValue(cutoff);
        if (!query.exec()) {
            if (error) {
                *error = query.lastError().text();
            }
            db.close();
            db = {};
            QSqlDatabase::removeDatabase(connectionName);
            return {};
        }

        QHash<QString, BrowserDomainStats> domains;
        while (query.next()) {
            const QString domain = normalizedBrowserDomain(query.value(0).toString());
            if (domain.isEmpty()) {
                continue;
            }
            BrowserDomainStats& stats = domains[domain];
            stats.domain = domain;
            stats.visits += std::max(1, query.value(1).toInt());
            stats.typed += query.value(2).toInt();
            stats.lastVisitTime = std::max(stats.lastVisitTime, query.value(3).toLongLong());
        }

        QList<BrowserDomainStats> ranked = domains.values();
        std::sort(ranked.begin(), ranked.end(), [](const BrowserDomainStats& left, const BrowserDomainStats& right) {
            const int leftScore = left.visits + left.typed * 3;
            const int rightScore = right.visits + right.typed * 3;
            if (leftScore != rightScore) {
                return leftScore > rightScore;
            }
            if (left.lastVisitTime != right.lastVisitTime) {
                return left.lastVisitTime > right.lastVisitTime;
            }
            return left.domain < right.domain;
        });

        for (const BrowserDomainStats& domain : ranked) {
            result.push_back(domain.domain);
            if (result.size() >= limit) {
                break;
            }
        }

        db.close();
    }
    QSqlDatabase::removeDatabase(connectionName);
    return result;
}

enum class BenchmarkProfile {
    Conservative = 0,
    HomeWifi = 1,
    WiredLan = 2,
    FastNetwork = 3,
    Custom = 4
};

struct BenchmarkProfileSettings {
    int delayMs = 100;
};

BenchmarkProfileSettings settingsForProfile(BenchmarkProfile profile)
{
    switch (profile) {
    case BenchmarkProfile::Conservative:
        return {200};
    case BenchmarkProfile::HomeWifi:
        return {150};
    case BenchmarkProfile::WiredLan:
        return {100};
    case BenchmarkProfile::FastNetwork:
        return {50};
    case BenchmarkProfile::Custom:
        break;
    }
    return {100};
}

BenchmarkProfile profileForSettings(int delayMs)
{
    for (BenchmarkProfile profile : {
             BenchmarkProfile::Conservative,
             BenchmarkProfile::HomeWifi,
             BenchmarkProfile::WiredLan,
             BenchmarkProfile::FastNetwork}) {
        const BenchmarkProfileSettings candidate = settingsForProfile(profile);
        if (candidate.delayMs == delayMs) {
            return profile;
        }
    }
    return BenchmarkProfile::Custom;
}

class PinnedSortProxyModel : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

    void setResultFilter(ResultFilter filter)
    {
        if (m_resultFilter == filter) {
            return;
        }
#if QT_VERSION >= QT_VERSION_CHECK(6, 10, 0)
        beginFilterChange();
        m_resultFilter = filter;
        endFilterChange(QSortFilterProxyModel::Direction::Rows);
#else
        m_resultFilter = filter;
        invalidateFilter();
#endif
    }

protected:
    bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override
    {
        if (m_resultFilter == ResultFilter::All) {
            return true;
        }

        const QModelIndex statusIndex = sourceModel()->index(sourceRow, ResolverModel::StatusColumn, sourceParent);
        const int rank = resultRank(sourceRow, sourceParent);
        switch (m_resultFilter) {
        case ResultFilter::All:
            return true;
        case ResultFilter::ReliableOnly:
            return rank == 0;
        case ResultFilter::UnreliableOnly:
            return rank == 1 || hasLatencyOutliers(sourceRow, sourceParent);
        case ResultFilter::NoResultOnly:
            return rank >= 3
                || static_cast<ResolverStatus>(statusIndex.data(Qt::UserRole).toInt()) == ResolverStatus::Running;
        }
        return true;
    }

    bool lessThan(const QModelIndex& left, const QModelIndex& right) const override
    {
        const bool leftPinned = sourceModel()->index(left.row(), ResolverModel::PinColumn).data(Qt::UserRole).toBool();
        const bool rightPinned = sourceModel()->index(right.row(), ResolverModel::PinColumn).data(Qt::UserRole).toBool();
        if (leftPinned != rightPinned) {
            return sortOrder() == Qt::AscendingOrder ? leftPinned : !leftPinned;
        }

        const int leftRank = sortRank(left.row());
        const int rightRank = sortRank(right.row());
        if (leftRank != rightRank) {
            return sortOrder() == Qt::AscendingOrder ? leftRank < rightRank : leftRank > rightRank;
        }

        switch (static_cast<ResolverModel::Column>(left.column())) {
        case ResolverModel::PinColumn:
        case ResolverModel::DisplayNameColumn:
        case ResolverModel::AddressColumn:
        case ResolverModel::ProtocolColumn:
        case ResolverModel::DnssecColumn:
        case ResolverModel::StatusColumn:
            return QString::localeAwareCompare(
                left.data(Qt::DisplayRole).toString(),
                right.data(Qt::DisplayRole).toString()) < 0;
        case ResolverModel::MedianColumn:
        case ResolverModel::P90Column:
        case ResolverModel::MeanColumn:
        case ResolverModel::StddevColumn:
        case ResolverModel::MinColumn:
        case ResolverModel::MaxColumn:
        case ResolverModel::LossColumn:
            if (left.data(Qt::UserRole).toDouble() != right.data(Qt::UserRole).toDouble()) {
                return left.data(Qt::UserRole).toDouble() < right.data(Qt::UserRole).toDouble();
            }
            return left.data(ResolverModel::UncachedValueRole).toDouble() < right.data(ResolverModel::UncachedValueRole).toDouble();
        case ResolverModel::TimelineColumn:
            return left.sibling(left.row(), ResolverModel::MedianColumn).data(Qt::UserRole).toDouble()
                < right.sibling(right.row(), ResolverModel::MedianColumn).data(Qt::UserRole).toDouble();
        case ResolverModel::ColumnCount:
            break;
        }
        return false;
    }

private:
    ResultFilter m_resultFilter = ResultFilter::All;

    int resultRank(int sourceRow, const QModelIndex& sourceParent = {}) const
    {
        const QModelIndex statusIndex = sourceModel()->index(sourceRow, ResolverModel::StatusColumn, sourceParent);
        const QModelIndex lossIndex = sourceModel()->index(sourceRow, ResolverModel::LossColumn, sourceParent);
        const auto status = static_cast<ResolverStatus>(statusIndex.data(Qt::UserRole).toInt());
        const bool hasSamples = statusIndex.data(ResolverModel::HasSamplesRole).toBool();
        const double lossPercent = lossIndex.data(Qt::UserRole).toDouble();

        switch (status) {
        case ResolverStatus::Finished:
            if (!hasSamples) {
                return 4;
            }
            return lossPercent <= 1.0 ? 0 : 1;
        case ResolverStatus::Running:
            return 2;
        case ResolverStatus::Sidelined:
        case ResolverStatus::Failed:
            return 3;
        case ResolverStatus::Stopped:
            return 4;
        case ResolverStatus::Idle:
        case ResolverStatus::Disabled:
            return 5;
        }
        return 5;
    }

    int sortRank(int sourceRow) const
    {
        return resultRank(sourceRow);
    }

    bool hasLatencyOutliers(int sourceRow, const QModelIndex& sourceParent = {}) const
    {
        const QModelIndex statusIndex = sourceModel()->index(sourceRow, ResolverModel::StatusColumn, sourceParent);
        if (!statusIndex.data(ResolverModel::HasSamplesRole).toBool()) {
            return false;
        }
        const auto status = static_cast<ResolverStatus>(statusIndex.data(Qt::UserRole).toInt());
        if (status != ResolverStatus::Finished) {
            return false;
        }
        const double lossPercent = sourceModel()->index(sourceRow, ResolverModel::LossColumn, sourceParent).data(Qt::UserRole).toDouble();
        const double medianMs = sourceModel()->index(sourceRow, ResolverModel::MedianColumn, sourceParent).data(Qt::UserRole).toDouble();
        const double stddevMs = sourceModel()->index(sourceRow, ResolverModel::StddevColumn, sourceParent).data(Qt::UserRole).toDouble();
        return lossPercent <= 1.0 && stddevMs > std::max(20.0, medianMs * 3.0);
    }
};

class LatencyBarDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        const auto status = static_cast<ResolverStatus>(index.sibling(index.row(), ResolverModel::StatusColumn).data(Qt::UserRole).toInt());
        if (status != ResolverStatus::Finished || !index.data(ResolverModel::HasSamplesRole).toBool()) {
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
        painter->setPen(QColor(33, 37, 43));
        painter->drawText(option.rect.adjusted(8, 0, -8, 0), Qt::AlignVCenter | Qt::AlignRight,
            QStringLiteral("%1 ms").arg(median, 0, 'f', 1));
        painter->restore();
    }
};

class TimelineSparklineDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        const QVector<ResolverSamplePoint> samples = index.data(Qt::UserRole).value<QVector<ResolverSamplePoint>>();
        if (samples.isEmpty()) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }

        QStyleOptionViewItem itemOption(option);
        initStyleOption(&itemOption, index);
        itemOption.text.clear();
        QStyle* style = itemOption.widget ? itemOption.widget->style() : QApplication::style();
        style->drawControl(QStyle::CE_ItemViewItem, &itemOption, painter, itemOption.widget);

        qreal maxRtt = 1.0;
        int successCount = 0;
        for (const ResolverSamplePoint& sample : samples) {
            if (sample.success) {
                ++successCount;
                maxRtt = std::max(maxRtt, static_cast<qreal>(std::max(1.0, sample.rttMs)));
            }
        }

        const double median = index.sibling(index.row(), ResolverModel::MedianColumn).data(Qt::UserRole).toDouble();
        const double p90 = index.sibling(index.row(), ResolverModel::P90Column).data(Qt::UserRole).toDouble();
        const double loss = index.sibling(index.row(), ResolverModel::LossColumn).data(Qt::UserRole).toDouble();
        const QColor quality = qualityColor(median, p90, loss);
        const QColor mutedQuality(quality.red(), quality.green(), quality.blue(), 60);
        const QColor lossColor = loss > 1.0 ? QColor(205, 67, 54) : QColor(183, 93, 52);

        const QRectF plot = option.rect.adjusted(6, 5, -6, -5);
        const qreal logMax = std::log10(std::max<qreal>(10.0, maxRtt));
        const int lastIndex = std::max(1, samples.last().sampleIndex);

        QPainterPath path;
        bool hasPoint = false;

        painter->save();
        painter->setRenderHint(QPainter::Antialiasing, true);
        painter->setPen(QPen(mutedQuality, 1));
        painter->drawLine(plot.left(), plot.center().y(), plot.right(), plot.center().y());

        for (const ResolverSamplePoint& sample : samples) {
            const qreal x = plot.left() + (plot.width() * sample.sampleIndex / lastIndex);
            if (!sample.success) {
                painter->setPen(QPen(lossColor, 2));
                painter->drawLine(QPointF(x, plot.bottom()), QPointF(x, plot.bottom() - std::max<qreal>(3.0, plot.height() * 0.22)));
                continue;
            }

            const qreal logValue = std::log10(std::max<qreal>(1.0, sample.rttMs));
            const qreal normalized = logMax <= 0.0 ? 0.0 : std::clamp(logValue / logMax, 0.0, 1.0);
            const qreal y = plot.bottom() - normalized * plot.height();
            if (!hasPoint) {
                path.moveTo(x, y);
                hasPoint = true;
            } else {
                path.lineTo(x, y);
            }
        }

        if (hasPoint) {
            painter->setPen(QPen(quality, 1.8));
            painter->drawPath(path);
        }

        if (successCount == 0) {
            painter->setPen(QPen(lossColor, 1.4));
            painter->drawLine(plot.bottomLeft(), plot.bottomRight());
        }

        painter->restore();
    }

private:
    static QColor blend(const QColor& from, const QColor& to, double t)
    {
        const double clamped = std::clamp(t, 0.0, 1.0);
        return QColor(
            static_cast<int>(from.red() + (to.red() - from.red()) * clamped),
            static_cast<int>(from.green() + (to.green() - from.green()) * clamped),
            static_cast<int>(from.blue() + (to.blue() - from.blue()) * clamped));
    }

    static QColor qualityColor(double medianMs, double p90Ms, double lossPercent)
    {
        const QColor green(57, 154, 89);
        const QColor amber(210, 154, 45);
        const QColor red(196, 69, 54);

        const double latencyScore = std::max(medianMs / 45.0, p90Ms / 120.0);
        const double lossScore = lossPercent / 5.0;
        const double score = std::max(latencyScore, lossScore);
        if (score <= 1.0) {
            return blend(green, amber, score);
        }
        return blend(amber, red, (score - 1.0) / 1.2);
    }
};

ResolverEntry publicResolver(
    const QString& family,
    const QString& name,
    const QString& address,
    ResolverProtocol protocol,
    int port = -1,
    const QString& notes = {})
{
    ResolverEntry entry;
    entry.displayName = name;
    entry.address = address;
    entry.protocol = protocol;
    entry.port = port > 0 ? port : defaultPortForProtocol(protocol);
    entry.builtInResolver = true;
    entry.providerFamily = family;
    entry.resolverNotes = notes;
    entry.id = ResolverModel::makeId(entry);
    return entry;
}

QString resolverPortDetailsLine(const ResolverEntry& entry)
{
    if (entry.protocol != ResolverProtocol::DoH) {
        return QStringLiteral("Port: %1").arg(entry.port);
    }

    QUrl url(entry.address);
    if (url.scheme().isEmpty()) {
        url = QUrl(QStringLiteral("https://%1/dns-query").arg(entry.address));
    }

    const bool explicitPort = url.port() > 0;
    const int effectivePort = explicitPort ? url.port() : entry.port;
    return explicitPort
        ? QStringLiteral("Endpoint port: %1 (from URL)").arg(effectivePort)
        : QStringLiteral("Endpoint port: %1").arg(effectivePort);
}

QList<ResolverEntry> builtInResolvers()
{
    return {
        publicResolver(QStringLiteral("Cloudflare"), QStringLiteral("Cloudflare 1.1.1.1"), QStringLiteral("1.1.1.1"), ResolverProtocol::IPv4, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Cloudflare"), QStringLiteral("Cloudflare 1.0.0.1"), QStringLiteral("1.0.0.1"), ResolverProtocol::IPv4, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Cloudflare"), QStringLiteral("Cloudflare IPv6"), QStringLiteral("2606:4700:4700::1111"), ResolverProtocol::IPv6, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Cloudflare"), QStringLiteral("Cloudflare DoH"), QStringLiteral("https://cloudflare-dns.com/dns-query"), ResolverProtocol::DoH, 443, QStringLiteral("General-purpose encrypted resolver.")),
        publicResolver(QStringLiteral("Cloudflare"), QStringLiteral("Cloudflare DoT"), QStringLiteral("1.1.1.1"), ResolverProtocol::DoT, 853, QStringLiteral("General-purpose encrypted resolver.")),
        publicResolver(QStringLiteral("Google"), QStringLiteral("Google 8.8.8.8"), QStringLiteral("8.8.8.8"), ResolverProtocol::IPv4, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Google"), QStringLiteral("Google 8.8.4.4"), QStringLiteral("8.8.4.4"), ResolverProtocol::IPv4, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Google"), QStringLiteral("Google IPv6"), QStringLiteral("2001:4860:4860::8888"), ResolverProtocol::IPv6, 53, QStringLiteral("General-purpose public resolver.")),
        publicResolver(QStringLiteral("Google"), QStringLiteral("Google DoH"), QStringLiteral("https://dns.google/dns-query"), ResolverProtocol::DoH, 443, QStringLiteral("General-purpose encrypted resolver.")),
        publicResolver(QStringLiteral("Google"), QStringLiteral("Google DoT"), QStringLiteral("8.8.8.8"), ResolverProtocol::DoT, 853, QStringLiteral("General-purpose encrypted resolver.")),
        publicResolver(QStringLiteral("Quad9"), QStringLiteral("Quad9 9.9.9.9"), QStringLiteral("9.9.9.9"), ResolverProtocol::IPv4, 53, QStringLiteral("Security-filtering resolver.")),
        publicResolver(QStringLiteral("Quad9"), QStringLiteral("Quad9 149.112.112.112"), QStringLiteral("149.112.112.112"), ResolverProtocol::IPv4, 53, QStringLiteral("Security-filtering resolver.")),
        publicResolver(QStringLiteral("Quad9"), QStringLiteral("Quad9 IPv6"), QStringLiteral("2620:fe::fe"), ResolverProtocol::IPv6, 53, QStringLiteral("Security-filtering resolver.")),
        publicResolver(QStringLiteral("Quad9"), QStringLiteral("Quad9 DoH"), QStringLiteral("https://dns.quad9.net/dns-query"), ResolverProtocol::DoH, 443, QStringLiteral("Security-filtering encrypted resolver.")),
        publicResolver(QStringLiteral("Quad9"), QStringLiteral("Quad9 DoT"), QStringLiteral("9.9.9.9"), ResolverProtocol::DoT, 853, QStringLiteral("Security-filtering encrypted resolver.")),
        publicResolver(QStringLiteral("OpenDNS"), QStringLiteral("OpenDNS 208.67.222.222"), QStringLiteral("208.67.222.222"), ResolverProtocol::IPv4, 53, QStringLiteral("Cisco public resolver with security filtering.")),
        publicResolver(QStringLiteral("OpenDNS"), QStringLiteral("OpenDNS 208.67.220.220"), QStringLiteral("208.67.220.220"), ResolverProtocol::IPv4, 53, QStringLiteral("Cisco public resolver with security filtering.")),
        publicResolver(QStringLiteral("AdGuard"), QStringLiteral("AdGuard 94.140.14.14"), QStringLiteral("94.140.14.14"), ResolverProtocol::IPv4, 53, QStringLiteral("Ad/tracker blocking resolver.")),
        publicResolver(QStringLiteral("AdGuard"), QStringLiteral("AdGuard 94.140.15.15"), QStringLiteral("94.140.15.15"), ResolverProtocol::IPv4, 53, QStringLiteral("Ad/tracker blocking resolver.")),
        publicResolver(QStringLiteral("AdGuard"), QStringLiteral("AdGuard DoH"), QStringLiteral("https://dns.adguard-dns.com/dns-query"), ResolverProtocol::DoH, 443, QStringLiteral("Ad/tracker blocking encrypted resolver.")),
        publicResolver(QStringLiteral("AdGuard"), QStringLiteral("AdGuard DoT"), QStringLiteral("94.140.14.14"), ResolverProtocol::DoT, 853, QStringLiteral("Ad/tracker blocking encrypted resolver.")),
        publicResolver(QStringLiteral("Control D"), QStringLiteral("Control D 76.76.2.0"), QStringLiteral("76.76.2.0"), ResolverProtocol::IPv4, 53, QStringLiteral("Configurable filtering resolver; p0 is unfiltered.")),
        publicResolver(QStringLiteral("Control D"), QStringLiteral("Control D 76.76.10.0"), QStringLiteral("76.76.10.0"), ResolverProtocol::IPv4, 53, QStringLiteral("Configurable filtering resolver; p0 is unfiltered.")),
        publicResolver(QStringLiteral("Control D"), QStringLiteral("Control D DoH"), QStringLiteral("https://freedns.controld.com/p0"), ResolverProtocol::DoH, 443, QStringLiteral("Unfiltered encrypted resolver profile.")),
    };
}

struct ImportResult {
    QList<ResolverEntry> entries;
    int skipped = 0;
    QStringList warnings;
};

QString normalizedColumnName(QString value)
{
    value = value.trimmed().toLower();
    value.remove(QRegularExpression(QStringLiteral("[^a-z0-9]")));
    return value;
}

bool parseLooseProtocol(const QString& value, ResolverProtocol* protocol)
{
    QString normalized = value.trimmed().toLower();
    normalized.remove(QString::fromUtf8("\xf0\x9f\x8c\x90"));
    normalized.remove(QString::fromUtf8("\xf0\x9f\x94\x92"));
    normalized = normalized.trimmed();
    if (normalized.contains(QStringLiteral("ipv4"))) {
        if (protocol) {
            *protocol = ResolverProtocol::IPv4;
        }
        return true;
    }
    if (normalized.contains(QStringLiteral("ipv6"))) {
        if (protocol) {
            *protocol = ResolverProtocol::IPv6;
        }
        return true;
    }
    if (normalized == QLatin1String("doh") || normalized.contains(QStringLiteral("https"))) {
        if (protocol) {
            *protocol = ResolverProtocol::DoH;
        }
        return true;
    }
    if (normalized == QLatin1String("dot") || normalized.contains(QStringLiteral("tls"))) {
        if (protocol) {
            *protocol = ResolverProtocol::DoT;
        }
        return true;
    }
    return false;
}

bool parseBoolToken(const QString& value, bool fallback)
{
    const QString normalized = value.trimmed().toLower();
    if (normalized == QLatin1String("1") || normalized == QLatin1String("true")
        || normalized == QLatin1String("yes") || normalized == QLatin1String("on")
        || normalized == QLatin1String("checked")) {
        return true;
    }
    if (normalized == QLatin1String("0") || normalized == QLatin1String("false")
        || normalized == QLatin1String("no") || normalized == QLatin1String("off")
        || normalized == QLatin1String("unchecked")) {
        return false;
    }
    return fallback;
}

bool isLikelyHostname(const QString& value)
{
    static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$"));
    return value.contains(QLatin1Char('.')) && pattern.match(value).hasMatch();
}

bool splitAddressPort(QString* address, int* port)
{
    QString value = address->trimmed();
    const QRegularExpression bracketedIpv6(QStringLiteral("^\\[([^\\]]+)\\]:(\\d{1,5})$"));
    const QRegularExpressionMatch bracketMatch = bracketedIpv6.match(value);
    if (bracketMatch.hasMatch()) {
        const int parsedPort = bracketMatch.captured(2).toInt();
        if (parsedPort >= 1 && parsedPort <= 65535) {
            *address = bracketMatch.captured(1);
            *port = parsedPort;
            return true;
        }
    }

    if (value.count(QLatin1Char(':')) == 1) {
        const int separator = value.lastIndexOf(QLatin1Char(':'));
        bool ok = false;
        const int parsedPort = value.mid(separator + 1).toInt(&ok);
        if (ok && parsedPort >= 1 && parsedPort <= 65535) {
            *address = value.left(separator);
            *port = parsedPort;
            return true;
        }
    }
    return false;
}

bool inferProtocol(const QString& address, ResolverProtocol* protocol)
{
    const QString trimmed = address.trimmed();
    QString candidateAddress = trimmed;
    int ignoredPort = 0;
    splitAddressPort(&candidateAddress, &ignoredPort);

    QHostAddress host;
    if (host.setAddress(candidateAddress)) {
        if (protocol) {
            *protocol = host.protocol() == QAbstractSocket::IPv6Protocol ? ResolverProtocol::IPv6 : ResolverProtocol::IPv4;
        }
        return true;
    }

    const QUrl url(trimmed);
    if (url.isValid() && (url.scheme() == QLatin1String("https") || url.scheme() == QLatin1String("http")) && !url.host().isEmpty()) {
        if (protocol) {
            *protocol = ResolverProtocol::DoH;
        }
        return true;
    }

    if (trimmed.contains(QLatin1Char('/')) || trimmed.contains(QStringLiteral("dns-query"))) {
        if (protocol) {
            *protocol = ResolverProtocol::DoH;
        }
        return true;
    }

    if (isLikelyHostname(trimmed)) {
        if (protocol) {
            *protocol = ResolverProtocol::DoT;
        }
        return true;
    }

    return false;
}

bool normalizeImportedResolver(ResolverEntry* entry, QString* reason)
{
    entry->displayName = entry->displayName.trimmed();
    entry->address = entry->address.trimmed();
    if (entry->address.isEmpty()) {
        if (reason) {
            *reason = QStringLiteral("missing address");
        }
        return false;
    }

    splitAddressPort(&entry->address, &entry->port);
    QHostAddress importedHost;
    if (importedHost.setAddress(entry->address)) {
        const ResolverProtocol inferredProtocol = importedHost.protocol() == QAbstractSocket::IPv6Protocol
            ? ResolverProtocol::IPv6
            : ResolverProtocol::IPv4;
        if (entry->protocol == ResolverProtocol::IPv4 || entry->protocol == ResolverProtocol::IPv6) {
            entry->protocol = inferredProtocol;
        }
    }
    if (entry->port <= 0 || entry->port > 65535) {
        entry->port = defaultPortForProtocol(entry->protocol);
    }

    if (entry->protocol == ResolverProtocol::IPv4 || entry->protocol == ResolverProtocol::IPv6) {
        QHostAddress host;
        if (!host.setAddress(entry->address)) {
            if (reason) {
                *reason = QStringLiteral("UDP resolvers must be IP addresses");
            }
            return false;
        }
        if (entry->protocol == ResolverProtocol::IPv4 && host.protocol() != QAbstractSocket::IPv4Protocol) {
            if (reason) {
                *reason = QStringLiteral("address is not IPv4");
            }
            return false;
        }
        if (entry->protocol == ResolverProtocol::IPv6 && host.protocol() != QAbstractSocket::IPv6Protocol) {
            if (reason) {
                *reason = QStringLiteral("address is not IPv6");
            }
            return false;
        }
    } else if (entry->protocol == ResolverProtocol::DoH) {
        QUrl url(entry->address.contains(QStringLiteral("://"))
                ? entry->address
                : QStringLiteral("https://%1/dns-query").arg(entry->address));
        if (!url.isValid() || url.scheme() != QLatin1String("https") || url.host().isEmpty()) {
            if (reason) {
                *reason = QStringLiteral("invalid DoH URL or host (HTTPS is required)");
            }
            return false;
        }
    } else if (entry->protocol == ResolverProtocol::DoT) {
        QHostAddress host;
        if (!host.setAddress(entry->address) && !isLikelyHostname(entry->address)) {
            if (reason) {
                *reason = QStringLiteral("invalid DoT IP address or hostname");
            }
            return false;
        }
    }

    entry->systemResolver = false;
    entry->builtInResolver = false;
    entry->status = ResolverStatus::Idle;
    entry->stats = {};
    entry->samples.clear();
    entry->dnssecAuthenticatedDataSeen = false;
    entry->id = ResolverModel::makeId(*entry);
    return true;
}

QStringList splitDelimitedLine(const QString& line, QChar delimiter)
{
    QStringList values;
    QString current;
    bool quoted = false;
    for (int i = 0; i < line.size(); ++i) {
        const QChar ch = line.at(i);
        if (ch == QLatin1Char('"')) {
            if (quoted && i + 1 < line.size() && line.at(i + 1) == QLatin1Char('"')) {
                current.append(ch);
                ++i;
            } else {
                quoted = !quoted;
            }
            continue;
        }
        if (ch == delimiter && !quoted) {
            values.push_back(current.trimmed());
            current.clear();
            continue;
        }
        current.append(ch);
    }
    values.push_back(current.trimmed());
    return values;
}

QStringList splitMarkdownRow(QString line)
{
    line = line.trimmed();
    if (line.startsWith(QLatin1Char('|'))) {
        line.remove(0, 1);
    }
    if (line.endsWith(QLatin1Char('|'))) {
        line.chop(1);
    }

    QStringList values;
    QString current;
    bool escaped = false;
    for (const QChar ch : line) {
        if (escaped) {
            current.append(ch);
            escaped = false;
            continue;
        }
        if (ch == QLatin1Char('\\')) {
            escaped = true;
            continue;
        }
        if (ch == QLatin1Char('|')) {
            values.push_back(current.trimmed());
            current.clear();
            continue;
        }
        current.append(ch);
    }
    values.push_back(current.trimmed());
    return values;
}

QChar delimiterForLine(const QString& line)
{
    if (line.contains(QLatin1Char('\t'))) {
        return QLatin1Char('\t');
    }
    if (line.contains(QLatin1Char(';')) && !line.contains(QLatin1Char(','))) {
        return QLatin1Char(';');
    }
    return QLatin1Char(',');
}

bool looksLikeHeader(const QStringList& values)
{
    bool hasAddress = false;
    bool hasProtocol = false;
    for (const QString& value : values) {
        const QString normalized = normalizedColumnName(value);
        hasAddress = hasAddress || normalized == QLatin1String("address")
            || normalized == QLatin1String("url") || normalized == QLatin1String("host")
            || normalized == QLatin1String("resolver") || normalized == QLatin1String("addressurl");
        hasProtocol = hasProtocol || normalized == QLatin1String("protocol")
            || normalized == QLatin1String("proto") || normalized == QLatin1String("type");
    }
    return hasAddress || hasProtocol;
}

int columnIndex(const QHash<QString, int>& columns, std::initializer_list<const char*> names)
{
    for (const char* name : names) {
        const auto it = columns.constFind(QString::fromLatin1(name));
        if (it != columns.cend()) {
            return it.value();
        }
    }
    return -1;
}

QString valueAt(const QStringList& values, int index)
{
    return index >= 0 && index < values.size() ? values.at(index).trimmed() : QString();
}

bool resolverFromHeaderRow(const QStringList& values, const QHash<QString, int>& columns, ResolverEntry* entry)
{
    const int addressIndex = columnIndex(columns, {"address", "url", "host", "resolver", "addressurl"});
    const QString address = valueAt(values, addressIndex);
    if (address.isEmpty()) {
        return false;
    }

    bool hasProtocol = false;
    ResolverProtocol protocol = ResolverProtocol::IPv4;
    const QString protocolText = valueAt(values, columnIndex(columns, {"protocol", "proto", "type"}));
    if (!protocolText.isEmpty()) {
        hasProtocol = parseLooseProtocol(protocolText, &protocol);
    }
    if (!hasProtocol && !inferProtocol(address, &protocol)) {
        return false;
    }

    bool portOk = false;
    const int port = valueAt(values, columnIndex(columns, {"port"})).toInt(&portOk);
    entry->address = address;
    entry->protocol = protocol;
    entry->port = portOk ? port : defaultPortForProtocol(protocol);
    entry->displayName = valueAt(values, columnIndex(columns, {"displayname", "name", "label"}));
    entry->pinned = parseBoolToken(valueAt(values, columnIndex(columns, {"pin", "pinned"})), false);
    entry->enabled = parseBoolToken(valueAt(values, columnIndex(columns, {"enabled"})), true);
    return true;
}

bool resolverFromLooseRow(const QStringList& rawValues, ResolverEntry* entry)
{
    QStringList values;
    for (const QString& value : rawValues) {
        const QString trimmed = value.trimmed();
        if (!trimmed.isEmpty()) {
            values.push_back(trimmed);
        }
    }
    if (values.isEmpty()) {
        return false;
    }

    if (values.size() == 1) {
        QString address = values.first();
        int port = defaultPortForProtocol(ResolverProtocol::IPv4);
        splitAddressPort(&address, &port);
        QHostAddress host;
        if (host.setAddress(address)) {
            entry->address = address;
            entry->protocol = host.protocol() == QAbstractSocket::IPv6Protocol ? ResolverProtocol::IPv6 : ResolverProtocol::IPv4;
            entry->port = port;
            entry->enabled = true;
            entry->pinned = false;
            return true;
        }
    }

    int protocolIndex = -1;
    ResolverProtocol protocol = ResolverProtocol::IPv4;
    for (int i = 0; i < values.size(); ++i) {
        if (parseLooseProtocol(values.at(i), &protocol)) {
            protocolIndex = i;
            break;
        }
    }

    int portIndex = -1;
    int port = 0;
    for (int i = 0; i < values.size(); ++i) {
        if (i == protocolIndex) {
            continue;
        }
        bool ok = false;
        const int parsed = values.at(i).toInt(&ok);
        if (ok && parsed >= 1 && parsed <= 65535) {
            portIndex = i;
            port = parsed;
            break;
        }
    }

    int addressIndex = -1;
    ResolverProtocol inferredProtocol = ResolverProtocol::IPv4;
    for (int i = 0; i < values.size(); ++i) {
        if (i == protocolIndex || i == portIndex) {
            continue;
        }
        ResolverProtocol candidateProtocol = ResolverProtocol::IPv4;
        if (inferProtocol(values.at(i), &candidateProtocol)) {
            addressIndex = i;
            inferredProtocol = candidateProtocol;
            break;
        }
    }
    if (addressIndex < 0) {
        return false;
    }

    if (protocolIndex < 0) {
        protocol = inferredProtocol;
    }

    QStringList nameParts;
    for (int i = 0; i < values.size(); ++i) {
        if (i != addressIndex && i != protocolIndex && i != portIndex) {
            nameParts.push_back(values.at(i));
        }
    }

    entry->address = values.at(addressIndex);
    entry->protocol = protocol;
    entry->port = portIndex >= 0 ? port : defaultPortForProtocol(protocol);
    entry->displayName = nameParts.join(QStringLiteral(" ")).trimmed();
    entry->enabled = true;
    entry->pinned = false;
    return true;
}

ImportResult parseResolverImport(const QByteArray& content)
{
    ImportResult result;
    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(content, &parseError);
    QJsonArray array;
    bool hasJsonResolverArray = false;
    if (parseError.error == QJsonParseError::NoError && document.isArray()) {
        array = document.array();
        hasJsonResolverArray = true;
    } else if (parseError.error == QJsonParseError::NoError && document.isObject()
        && document.object().value(QStringLiteral("resolvers")).isArray()) {
        array = document.object().value(QStringLiteral("resolvers")).toArray();
        hasJsonResolverArray = true;
    }
    if (hasJsonResolverArray) {
        for (int i = 0; i < array.size(); ++i) {
            if (!array.at(i).isObject()) {
                ++result.skipped;
                continue;
            }
            const QJsonObject object = array.at(i).toObject();
            ResolverEntry entry;
            entry.displayName = object.value(QStringLiteral("displayName")).toString(object.value(QStringLiteral("name")).toString());
            entry.address = object.value(QStringLiteral("address")).toString(object.value(QStringLiteral("url")).toString());
            ResolverProtocol protocol = ResolverProtocol::IPv4;
            if (!parseLooseProtocol(object.value(QStringLiteral("protocol")).toString(), &protocol)
                && !inferProtocol(entry.address, &protocol)) {
                ++result.skipped;
                result.warnings.push_back(QStringLiteral("JSON row %1 skipped: missing or unknown protocol.").arg(i + 1));
                continue;
            }
            entry.protocol = protocol;
            entry.port = object.value(QStringLiteral("port")).toInt(defaultPortForProtocol(protocol));
            entry.pinned = object.value(QStringLiteral("pinned")).toBool(false);
            entry.enabled = object.value(QStringLiteral("enabled")).toBool(true);

            QString reason;
            if (normalizeImportedResolver(&entry, &reason)) {
                result.entries.push_back(entry);
            } else {
                ++result.skipped;
                result.warnings.push_back(QStringLiteral("JSON row %1 skipped: %2.").arg(i + 1).arg(reason));
            }
        }
        return result;
    }
    const QString text = QString::fromUtf8(content);
    QStringList header;
    QHash<QString, int> columns;
    int lineNumber = 0;

    for (QString line : text.split(QLatin1Char('\n'))) {
        ++lineNumber;
        line = line.trimmed();
        if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) {
            continue;
        }

        QStringList values;
        if (line.startsWith(QLatin1Char('|'))) {
            values = splitMarkdownRow(line);
            bool separator = true;
            for (const QString& value : values) {
                separator = separator && value.contains(QLatin1String("---"));
            }
            if (separator) {
                continue;
            }
        } else {
            values = splitDelimitedLine(line, delimiterForLine(line));
        }

        if (header.isEmpty() && looksLikeHeader(values)) {
            header = values;
            for (int i = 0; i < header.size(); ++i) {
                columns.insert(normalizedColumnName(header.at(i)), i);
            }
            continue;
        }

        ResolverEntry entry;
        const bool parsed = !header.isEmpty()
            ? resolverFromHeaderRow(values, columns, &entry)
            : resolverFromLooseRow(values, &entry);
        if (!parsed) {
            ++result.skipped;
            continue;
        }

        QString reason;
        if (normalizeImportedResolver(&entry, &reason)) {
            result.entries.push_back(entry);
        } else {
            ++result.skipped;
            if (result.warnings.size() < 8) {
                result.warnings.push_back(QStringLiteral("Line %1 skipped: %2.").arg(lineNumber).arg(reason));
            }
        }
    }

    return result;
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

bool isReliableResult(const ResolverEntry& entry)
{
    return resolverIsReliable(entry);
}

bool resultLessThan(const ResolverEntry& left, const ResolverEntry& right)
{
    const bool leftHasSamples = left.stats.hasSamples();
    const bool rightHasSamples = right.stats.hasSamples();
    if (leftHasSamples != rightHasSamples) {
        return leftHasSamples;
    }
    const bool leftReliable = isReliableResult(left);
    const bool rightReliable = isReliableResult(right);
    if (leftReliable != rightReliable) {
        return leftReliable;
    }
    if (!leftReliable && left.stats.lossPercent != right.stats.lossPercent) {
        return left.stats.lossPercent < right.stats.lossPercent;
    }
    if (left.stats.medianMs != right.stats.medianMs) {
        return left.stats.medianMs < right.stats.medianMs;
    }
    if (left.uncachedStats.hasSamples() && right.uncachedStats.hasSamples()
        && left.uncachedStats.medianMs != right.uncachedStats.medianMs) {
        return left.uncachedStats.medianMs < right.uncachedStats.medianMs;
    }
    if (left.stats.p90Ms != right.stats.p90Ms) {
        return left.stats.p90Ms < right.stats.p90Ms;
    }
    return left.stats.meanMs < right.stats.meanMs;
}

QToolButton* addMenuButton(QToolBar* toolbar, const QString& text, QMenu* menu)
{
    auto* button = new ToolbarMenuButton(toolbar);
    button->setText(text);
    button->setPopupMode(QToolButton::InstantPopup);
    button->setToolButtonStyle(Qt::ToolButtonTextOnly);
    button->setMenu(menu);
    toolbar->addWidget(button);
    return button;
}

}

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    buildUi();
    connectController();
    loadSettings();
    QTimer::singleShot(0, this, &MainWindow::finishStartup);
}

MainWindow::~MainWindow()
{
    prepareForExit();
}

void MainWindow::prepareForExit()
{
    if (m_preparedForExit) {
        return;
    }
    m_preparedForExit = true;

    if (m_controller.isRunning()) {
        disconnect(&m_controller, nullptr, this, nullptr);
        m_controller.stop();
    }
    saveSettings();
}

void MainWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);
    if (event->type() == QEvent::PaletteChange || event->type() == QEvent::StyleChange) {
        applyToolbarTheme();
    }
}

void MainWindow::applyToolbarTheme()
{
    if (QToolBar* toolbar = findChild<QToolBar*>(QStringLiteral("benchmarkToolbar"))) {
        toolbar->setStyleSheet(QStringLiteral(R"css(
            QToolBar#benchmarkToolbar {
                background: palette(window);
                color: palette(window-text);
                border: 0;
                border-bottom: 1px solid palette(mid);
                spacing: 2px;
                padding: 2px;
            }
            QToolBar#benchmarkToolbar QToolButton {
                background: transparent;
                color: palette(window-text);
                border: 1px solid transparent;
                border-radius: 3px;
                padding: 4px 6px;
            }
            QToolBar#benchmarkToolbar QToolButton[toolbarMenu="true"] {
                padding-right: 18px;
            }
            QToolBar#benchmarkToolbar QToolButton[toolbarMenu="true"]::menu-indicator {
                image: none;
                width: 0;
                height: 0;
            }
            QToolBar#benchmarkToolbar QToolButton:hover {
                background: palette(alternate-base);
                border-color: palette(mid);
            }
            QToolBar#benchmarkToolbar QToolButton:pressed {
                background: palette(highlight);
                color: palette(highlighted-text);
            }
            QToolBar#benchmarkToolbar QLabel,
            QToolBar#benchmarkToolbar QCheckBox {
                color: palette(window-text);
            }
            QToolBar#benchmarkToolbar QComboBox,
            QToolBar#benchmarkToolbar QSpinBox {
                background: palette(base);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 3px;
                padding: 2px 4px;
            }
            QToolBar#benchmarkToolbar QComboBox::drop-down,
            QToolBar#benchmarkToolbar QSpinBox::up-button,
            QToolBar#benchmarkToolbar QSpinBox::down-button {
                border: 0;
                background: transparent;
            }
        )css"));
    }
}

void MainWindow::updateRunAction()
{
    if (!m_runButton) {
        return;
    }
    m_runButton->setText(m_controller.isRunning() ? QStringLiteral("Stop") : QStringLiteral("Start"));
    m_runButton->setToolTip(m_controller.isRunning()
            ? QStringLiteral("Stop the current benchmark")
            : QStringLiteral("Start the benchmark"));
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
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setSectionResizeMode(ResolverModel::TimelineColumn, QHeaderView::Fixed);
    m_table->setColumnWidth(ResolverModel::TimelineColumn, 150);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setItemDelegateForColumn(ResolverModel::MedianColumn, new LatencyBarDelegate(m_table));
    m_table->setItemDelegateForColumn(ResolverModel::TimelineColumn, new TimelineSparklineDelegate(m_table));
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_table, &QTableView::customContextMenuRequested, this, &MainWindow::showResolverContextMenu);
    connect(m_table, &QTableView::clicked, this, &MainWindow::openTimelineForIndex);
    connect(m_table, &QTableView::doubleClicked, this, &MainWindow::showResolverDetailsForIndex);
    auto* removeSelectedAction = new QAction(QStringLiteral("Remove Selected Resolvers"), this);
    removeSelectedAction->setShortcut(QKeySequence::Delete);
    removeSelectedAction->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    connect(removeSelectedAction, &QAction::triggered, this, &MainWindow::removeSelectedResolvers);
    m_table->addAction(removeSelectedAction);

    m_resultsTab = new ResultsTab(this);
    m_log = new QPlainTextEdit(this);
    m_log->setReadOnly(true);
    m_log->document()->setMaximumBlockCount(5000);
    m_log->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_log, &QPlainTextEdit::customContextMenuRequested, this, [this](const QPoint& position) {
        std::unique_ptr<QMenu> menu(m_log->createStandardContextMenu());
        menu->addSeparator();
        menu->addAction(QStringLiteral("Clear Log"), this, [this]() {
            m_log->clear();
        });
        menu->exec(m_log->viewport()->mapToGlobal(position));
    });
    QFont monospace(QStringLiteral("monospace"));
    monospace.setStyleHint(QFont::Monospace);
    m_log->setFont(monospace);

    m_domainsEditor = new QPlainTextEdit(this);
    m_domainsEditor->setLineWrapMode(QPlainTextEdit::NoWrap);
    m_domainsEditor->setFont(monospace);
    m_domainsEditor->setPlainText(defaultDomains().join(QLatin1Char('\n')));

    auto* tabs = new QTabWidget(this);
    tabs->addTab(m_resultsTab, QStringLiteral("Results"));
    tabs->addTab(m_log, QStringLiteral("Log"));
    tabs->addTab(m_domainsEditor, QStringLiteral("Sites"));

    m_modelFlushTimer = new QTimer(this);
    m_modelFlushTimer->setInterval(100);
    connect(m_modelFlushTimer, &QTimer::timeout, this, &MainWindow::flushPendingModelUpdates);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    splitter->addWidget(m_table);
    splitter->addWidget(tabs);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 1);
    setCentralWidget(splitter);

    auto* toolbar = addToolBar(QStringLiteral("Benchmark"));
    toolbar->setObjectName(QStringLiteral("benchmarkToolbar"));
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(16, 16));
    auto* runButton = new QPushButton(QStringLiteral("Start"), this);
    runButton->setMinimumWidth(80);
    connect(runButton, &QPushButton::clicked, this, [this]() {
        if (m_controller.isRunning()) {
            stopBenchmark();
        } else {
            startBenchmark();
        }
    });
    toolbar->addWidget(runButton);
    m_runButton = runButton;
    toolbar->addSeparator();

    auto* resolverMenu = new QMenu(toolbar);
    resolverMenu->addAction(QStringLiteral("Add Resolver"), this, &MainWindow::addResolver);
    QAction* importAction = resolverMenu->addAction(QStringLiteral("Import"), this, &MainWindow::importResolvers);
    importAction->setToolTip(QStringLiteral("Import resolvers from CSV, TSV, Markdown, JSON, or one resolver per line."));
    resolverMenu->addAction(QStringLiteral("Detect System DNS"), this, &MainWindow::detectSystemDns);
    resolverMenu->addAction(QStringLiteral("Restore Built-ins"), this, &MainWindow::restoreBuiltInResolvers);
    addMenuButton(toolbar, QStringLiteral("Resolvers"), resolverMenu);

    auto* resultsMenu = new QMenu(toolbar);
    resultsMenu->addAction(QStringLiteral("Export"), this, &MainWindow::exportResults);
    resultsMenu->addAction(QStringLiteral("Copy Results"), this, &MainWindow::cloneResults);
    addMenuButton(toolbar, QStringLiteral("Results"), resultsMenu);

    auto* sitesMenu = new QMenu(toolbar);
    sitesMenu->addAction(QStringLiteral("Save Test Sites"), this, &MainWindow::saveTestSites);
    sitesMenu->addAction(QStringLiteral("Import from Browser"), this, &MainWindow::importSitesFromBrowser);
    sitesMenu->addAction(QStringLiteral("Reset Test Sites"), this, &MainWindow::resetTestSites);
    addMenuButton(toolbar, QStringLiteral("Sites"), sitesMenu);
    toolbar->addSeparator();

    m_ipv4Toggle = new QCheckBox(QStringLiteral("IPv4"), this);
    m_ipv6Toggle = new QCheckBox(QStringLiteral("IPv6"), this);
    m_dohToggle = new QCheckBox(QStringLiteral("DoH"), this);
    m_dotToggle = new QCheckBox(QStringLiteral("DoT"), this);
    m_uncachedToggle = new QCheckBox(QStringLiteral("Uncached"), this);
    m_uncachedToggle->setToolTip(QStringLiteral("Also run a second pass with random names under wildcard DNS zones."));
    for (QCheckBox* box : {m_ipv4Toggle, m_ipv6Toggle, m_dohToggle, m_dotToggle, m_uncachedToggle}) {
        if (box != m_uncachedToggle) {
            box->setChecked(true);
        }
        toolbar->addWidget(box);
    }
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Show"), this));
    m_resultFilterCombo = new QComboBox(this);
    m_resultFilterCombo->addItem(QStringLiteral("All results"), static_cast<int>(ResultFilter::All));
    m_resultFilterCombo->addItem(QStringLiteral("Reliable only"), static_cast<int>(ResultFilter::ReliableOnly));
    m_resultFilterCombo->addItem(QStringLiteral("Loss / outliers"), static_cast<int>(ResultFilter::UnreliableOnly));
    m_resultFilterCombo->addItem(QStringLiteral("No result"), static_cast<int>(ResultFilter::NoResultOnly));
    m_resultFilterCombo->setToolTip(QStringLiteral("Filter visible resolver rows by measured result quality."));
    m_resultFilterCombo->setMaximumWidth(140);
    connect(m_resultFilterCombo, &QComboBox::currentIndexChanged, this, [this]() {
        if (auto* proxy = dynamic_cast<PinnedSortProxyModel*>(m_proxy)) {
            proxy->setResultFilter(static_cast<ResultFilter>(m_resultFilterCombo->currentData().toInt()));
        }
    });
    toolbar->addWidget(m_resultFilterCombo);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Samples"), this));
    m_sampleSpin = new QSpinBox(this);
    m_sampleSpin->setRange(1, 25000);
    m_sampleSpin->setValue(250);
    m_sampleSpin->setMaximumWidth(88);
    toolbar->addWidget(m_sampleSpin);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Passes"), this));
    m_passSpin = new QSpinBox(this);
    m_passSpin->setRange(1, 5);
    m_passSpin->setValue(1);
    m_passSpin->setToolTip(QStringLiteral("Repeat the same benchmark to check whether rankings are stable."));
    m_passSpin->setMaximumWidth(58);
    toolbar->addWidget(m_passSpin);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Net"), this));
    m_benchmarkProfileCombo = new QComboBox(this);
    m_benchmarkProfileCombo->addItem(QStringLiteral("Conservative"), static_cast<int>(BenchmarkProfile::Conservative));
    m_benchmarkProfileCombo->addItem(QStringLiteral("Home / Wi-Fi"), static_cast<int>(BenchmarkProfile::HomeWifi));
    m_benchmarkProfileCombo->addItem(QStringLiteral("Wired / LAN"), static_cast<int>(BenchmarkProfile::WiredLan));
    m_benchmarkProfileCombo->addItem(QStringLiteral("Fast"), static_cast<int>(BenchmarkProfile::FastNetwork));
    m_benchmarkProfileCombo->addItem(QStringLiteral("Custom"), static_cast<int>(BenchmarkProfile::Custom));
    m_benchmarkProfileCombo->setToolTip(QStringLiteral("Chooses the default delay between queries for the network environment."));
    m_benchmarkProfileCombo->setMaximumWidth(130);
    toolbar->addWidget(m_benchmarkProfileCombo);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Delay"), this));
    m_delaySpin = new QSpinBox(this);
    m_delaySpin->setRange(0, 5000);
    m_delaySpin->setValue(settingsForProfile(BenchmarkProfile::WiredLan).delayMs);
    m_delaySpin->setSuffix(QStringLiteral(" ms"));
    m_delaySpin->setToolTip(QStringLiteral("Global delay between round-robin queries."));
    m_delaySpin->setMaximumWidth(92);
    toolbar->addWidget(m_delaySpin);

    const int wiredProfileIndex = m_benchmarkProfileCombo->findData(static_cast<int>(BenchmarkProfile::WiredLan));
    m_benchmarkProfileCombo->setCurrentIndex(wiredProfileIndex >= 0 ? wiredProfileIndex : 0);
    connect(m_benchmarkProfileCombo, &QComboBox::currentIndexChanged, this, [this]() {
        applyBenchmarkProfile(m_benchmarkProfileCombo->currentData().toInt());
    });
    connect(m_delaySpin, &QSpinBox::valueChanged, this, [this]() {
        markBenchmarkProfileCustom();
    });

    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_etaLabel = new QLabel(QStringLiteral("0/0 queries | ETA: -"), this);
    m_verboseLogToggle = new QCheckBox(QStringLiteral("Verbose Log"), this);
    m_verboseLogToggle->setToolTip(QStringLiteral("Log every query and response. Leave off for smoother large benchmarks."));
    statusBar()->addPermanentWidget(m_verboseLogToggle);
    auto* statusSeparator = new QFrame(this);
    statusSeparator->setFrameShape(QFrame::VLine);
    statusSeparator->setFrameShadow(QFrame::Plain);
    statusSeparator->setFixedHeight(fontMetrics().height() + 6);
    statusBar()->addPermanentWidget(statusSeparator);
    statusBar()->addPermanentWidget(m_etaLabel);
    statusBar()->addPermanentWidget(m_progress, 1);

    menuBar()->hide();
    applyToolbarTheme();
    updateRunAction();
}

void MainWindow::connectController()
{
    connect(&m_controller, &BenchmarkController::progressUpdated, this, &MainWindow::updateProgress);
    connect(&m_controller, &BenchmarkController::resolverFinished, this, &MainWindow::queueResolverFinished);
    connect(&m_controller, &BenchmarkController::resolverStatusChanged, this, &MainWindow::queueResolverStatus);
    connect(&m_controller, &BenchmarkController::logLine, this, &MainWindow::appendLogLine);
    connect(&m_controller, &BenchmarkController::benchmarkFinished, this, [this]() {
        while (!m_pendingStatusUpdates.isEmpty() || !m_pendingResolverUpdates.isEmpty()) {
            flushPendingModelUpdates();
        }
        m_modelFlushTimer->stop();
        if (m_currentPass > 0 && m_currentPass < m_requestedPasses && !m_repeatRunEntries.isEmpty()) {
            ++m_currentPass;
            startBenchmarkPass(true);
            return;
        }
        finishBenchmarkRun();
    });
}

void MainWindow::finishStartup()
{
    detectSystemDns();
    addBuiltInResolvers();
    m_table->resizeColumnsToContents();
    m_table->horizontalHeader()->setSectionResizeMode(ResolverModel::TimelineColumn, QHeaderView::Fixed);
    m_table->setColumnWidth(ResolverModel::TimelineColumn, 150);
}

void MainWindow::finishBenchmarkRun()
{
    applyRepeatedPassAggregates();
    m_currentPass = 0;
    m_repeatRunEntries.clear();
    m_requestedPasses = 1;

    m_proxy->setDynamicSortFilter(true);
    m_proxy->sort(m_table->horizontalHeader()->sortIndicatorSection(), m_table->horizontalHeader()->sortIndicatorOrder());
    updateConclusions();
    updateRunAction();
}

void MainWindow::applyRepeatedPassAggregates()
{
    if (m_requestedPasses <= 1) {
        return;
    }

    for (const ResolverEntry& entry : std::as_const(m_repeatRunEntries)) {
        const QVector<QVector<ResolverSamplePoint>> passSamples = m_repeatPassSamples.value(entry.id);
        const QVector<Statistics> passStats = m_repeatPassStats.value(entry.id);
        if (passSamples.size() < 2 || passStats.size() < 2) {
            continue;
        }

        const Statistics aggregateStats = aggregateStatsForPasses(passSamples, passStats);
        const QVector<ResolverSamplePoint> combinedSamples = combinePassSamples(passSamples, passStats);
        const QVector<Statistics> uncachedPassStats = m_repeatUncachedPassStats.value(entry.id);
        const QVector<QVector<ResolverSamplePoint>> uncachedPassSamples = m_repeatUncachedPassSamples.value(entry.id);
        m_model.updateStats(
            entry.id,
            aggregateStats,
            aggregateStatusForPasses(m_repeatPassStatuses.value(entry.id)),
            m_repeatDnssecSeen.value(entry.id, false),
            combinedSamples,
            passSamples,
            aggregateStatsForPasses(uncachedPassSamples, uncachedPassStats),
            combinePassSamples(uncachedPassSamples, uncachedPassStats),
            uncachedPassSamples);
    }
}

void MainWindow::startBenchmarkPass(bool resetRuntimeState)
{
    if (resetRuntimeState) {
        for (const ResolverEntry& entry : std::as_const(m_repeatRunEntries)) {
            m_model.resetRuntimeState(entry.id);
        }
    }

    m_pendingResolverUpdates.clear();
    m_pendingStatusUpdates.clear();
    m_progress->setValue(0);
    const QString passText = m_requestedPasses > 1
        ? QStringLiteral(" pass %1/%2").arg(m_currentPass).arg(m_requestedPasses)
        : QString();
    appendLogLine(QStringLiteral("Starting benchmark%1.").arg(passText));
    m_controller.setVerboseLogging(m_verboseLogToggle->isChecked());
    const bool primeCache = m_requestedPasses <= 1 || m_currentPass <= 1;
    m_controller.start(m_repeatRunEntries, m_sampleSpin->value(), m_delaySpin->value(), loadDomains(), primeCache, m_uncachedToggle->isChecked());
    updateRunAction();
}

void MainWindow::beginBenchmarkRun(const QList<ResolverEntry>& runEntries, const QString& summary, const QString& logLine, bool resetAllRuntimeState)
{
    m_modelFlushTimer->stop();
    m_pendingResolverUpdates.clear();
    m_pendingStatusUpdates.clear();
    m_repeatPassStats.clear();
    m_repeatPassSamples.clear();
    m_repeatUncachedPassStats.clear();
    m_repeatUncachedPassSamples.clear();
    m_repeatPassStatuses.clear();
    m_repeatDnssecSeen.clear();
    m_repeatRunEntries = runEntries;
    m_requestedPasses = m_passSpin->value();
    m_currentPass = 1;
    m_currentRunIds.clear();
    for (const ResolverEntry& entry : runEntries) {
        m_currentRunIds.insert(entry.id);
    }

    m_proxy->setDynamicSortFilter(false);
    if (resetAllRuntimeState) {
        m_model.resetRuntimeState();
    } else {
        for (const ResolverEntry& entry : std::as_const(runEntries)) {
            m_model.setResolverEnabled(entry.id, true);
            m_model.resetRuntimeState(entry.id);
        }
    }
    m_progress->setValue(0);
    m_resultsTab->setSummary(summary);
    appendLogLine(logLine);
    startBenchmarkPass(false);
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
        if (m_hiddenBuiltInResolverIds.contains(entry.id)) {
            continue;
        }
        if (!m_model.find(entry.id)) {
            m_model.addResolver(entry);
            ++added;
        }
    }
    appendLogLine(QStringLiteral("Added %1 built-in public resolver(s).").arg(added));
}

void MainWindow::restoreBuiltInResolvers()
{
    m_hiddenBuiltInResolverIds.clear();
    addBuiltInResolvers();
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

void MainWindow::importResolvers()
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before importing resolvers."));
        return;
    }

    const QString path = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("Import Resolvers"),
        QString(),
        QStringLiteral("Resolver Lists (*.csv *.tsv *.txt *.md *.json);;All Files (*)"));
    if (path.isEmpty()) {
        return;
    }

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, QStringLiteral("Import Failed"), file.errorString());
        return;
    }

    ImportResult import = parseResolverImport(file.readAll());
    QSet<QString> seen;
    for (const ResolverEntry& entry : m_model.entries()) {
        seen.insert(entry.id);
    }

    QList<ResolverEntry> toAdd;
    toAdd.reserve(import.entries.size());
    int duplicates = 0;
    for (const ResolverEntry& entry : std::as_const(import.entries)) {
        if (seen.contains(entry.id)) {
            ++duplicates;
            continue;
        }
        seen.insert(entry.id);
        toAdd.push_back(entry);
    }

    if (!toAdd.isEmpty()) {
        m_model.addResolvers(toAdd);
    }

    appendLogLine(QStringLiteral("Imported %1 resolver(s) from %2. Skipped %3 invalid row(s), %4 duplicate(s).")
        .arg(toAdd.size())
        .arg(QFileInfo(path).fileName())
        .arg(import.skipped)
        .arg(duplicates));

    QString message = QStringLiteral("Imported %1 resolver(s).\nSkipped %2 invalid row(s), %3 duplicate(s).")
        .arg(toAdd.size())
        .arg(import.skipped)
        .arg(duplicates);
    if (!import.warnings.isEmpty()) {
        message += QStringLiteral("\n\nFirst issues:\n%1").arg(import.warnings.join(QStringLiteral("\n")));
    }
    QMessageBox::information(this, QStringLiteral("Import Complete"), message);
}

void MainWindow::startBenchmark()
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before starting another one."));
        return;
    }

    m_model.setProtocolEnabled(ResolverProtocol::IPv4, m_ipv4Toggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::IPv6, m_ipv6Toggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::DoH, m_dohToggle->isChecked());
    m_model.setProtocolEnabled(ResolverProtocol::DoT, m_dotToggle->isChecked());
    const QList<ResolverEntry> runEntries = m_model.enabledEntries();
    if (runEntries.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("No Resolvers"), QStringLiteral("No resolvers are enabled for this benchmark."));
        return;
    }
    beginBenchmarkRun(
        runEntries,
        m_passSpin->value() > 1
            ? QStringLiteral("Benchmark running (%1 passes)...").arg(m_passSpin->value())
            : QStringLiteral("Benchmark running..."),
        QStringLiteral("Preparing benchmark."),
        true);
}

void MainWindow::startBenchmarkForResolver(const ResolverEntry& entry)
{
    startBenchmarkForResolvers({entry});
}

void MainWindow::startBenchmarkForResolvers(const QList<ResolverEntry>& entries)
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before starting another one."));
        return;
    }

    QList<ResolverEntry> runEntries;
    runEntries.reserve(entries.size());
    QSet<QString> seen;
    for (ResolverEntry entry : entries) {
        if (entry.id.isEmpty() || seen.contains(entry.id)) {
            continue;
        }
        entry.enabled = true;
        seen.insert(entry.id);
        runEntries.push_back(entry);
    }

    if (runEntries.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("No Resolvers"), QStringLiteral("No resolvers were selected for this benchmark."));
        return;
    }

    beginBenchmarkRun(
        runEntries,
        runEntries.size() == 1
            ? QStringLiteral("Benchmark running for %1...").arg(runEntries.first().effectiveName())
            : QStringLiteral("Benchmark running for %1 selected resolvers...").arg(runEntries.size()),
        runEntries.size() == 1
            ? QStringLiteral("Starting single-resolver benchmark for %1.").arg(runEntries.first().effectiveName())
            : QStringLiteral("Starting selected-resolver benchmark for %1 resolvers.").arg(runEntries.size()),
        false);
}

void MainWindow::stopBenchmark()
{
    const QList<ResolverEntry> stoppedEntries = m_repeatRunEntries;
    m_currentPass = 0;
    m_repeatRunEntries.clear();
    m_pendingStatusUpdates.clear();
    m_pendingResolverUpdates.clear();
    m_modelFlushTimer->stop();
    for (const ResolverEntry& entry : stoppedEntries) {
        m_model.updateStatus(entry.id, ResolverStatus::Stopped);
    }
    m_controller.stop();
    updateRunAction();
}

void MainWindow::exportResults()
{
    const QString path = QFileDialog::getSaveFileName(this, QStringLiteral("Export Results"), QStringLiteral("dnsbench-results.csv"), QStringLiteral("CSV (*.csv);;Markdown Table (*.md *.txt)"));
    if (path.isEmpty()) {
        return;
    }

    QString error;
    const bool markdownExport = path.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive)
        || path.endsWith(QStringLiteral(".md"), Qt::CaseInsensitive);
    const bool ok = markdownExport
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
    dialog->setWindowTitle(QStringLiteral("Copy Results"));
    dialog->resize(1000, 500);

    const QString markdown = ResultExporter::toTextTable(m_model.entries());
    const bool renderMarkdown = m_model.rowCount() <= renderedMarkdownRowLimit;
    QWidget* text = nullptr;
    if (renderMarkdown) {
        auto* browser = new QTextBrowser(dialog);
        browser->setOpenExternalLinks(false);
        browser->setMarkdown(markdown);
        text = browser;
    } else {
        auto* editor = new QPlainTextEdit(dialog);
        editor->setReadOnly(true);
        editor->setLineWrapMode(QPlainTextEdit::NoWrap);
        editor->setPlainText(markdown);
        text = editor;
    }

    auto* copyButton = new QPushButton(QStringLiteral("Copy Markdown"), dialog);
    connect(copyButton, &QPushButton::clicked, dialog, [markdown]() {
        QApplication::clipboard()->setText(markdown);
    });

    auto* controls = new QHBoxLayout();
    if (!renderMarkdown) {
        controls->addWidget(new QLabel(QStringLiteral("Large result set shown as plain text for responsiveness."), dialog));
    }
    controls->addStretch();
    controls->addWidget(copyButton);

    auto* layout = new QVBoxLayout(dialog);
    layout->addLayout(controls);
    layout->addWidget(text);
    dialog->show();
}

void MainWindow::saveTestSites()
{
    QSettings settings;
    settings.setValue(QStringLiteral("benchmark/testSites"), m_domainsEditor->toPlainText());
    appendLogLine(QStringLiteral("Saved test site list."));
    QMessageBox::information(this, QStringLiteral("Sites Saved"), QStringLiteral("The current Sites list has been saved."));
}

void MainWindow::importSitesFromBrowser()
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before importing test sites."));
        return;
    }

    const QList<BrowserHistorySource> sources = browserHistorySources();
    if (sources.isEmpty()) {
        QMessageBox::information(
            this,
            QStringLiteral("No Browser History Found"),
            QStringLiteral("No Chromium-family browser history databases were found. Supported profiles include Chrome, Chromium, Brave, Edge, Vivaldi, and Opera."));
        return;
    }

    QStringList labels;
    labels.reserve(sources.size());
    for (const BrowserHistorySource& source : sources) {
        labels.push_back(QStringLiteral("%1 (%2)").arg(source.label(), source.historyPath));
    }

    bool ok = false;
    const QString selected = QInputDialog::getItem(
        this,
        QStringLiteral("Import Sites from Browser"),
        QStringLiteral("Browser profile"),
        labels,
        0,
        false,
        &ok);
    if (!ok || selected.isEmpty()) {
        return;
    }

    const int selectedIndex = labels.indexOf(selected);
    if (selectedIndex < 0 || selectedIndex >= sources.size()) {
        return;
    }

    QString error;
    const QStringList domains = domainsFromChromiumHistory(
        sources.at(selectedIndex).historyPath,
        browserImportDefaultLimit,
        browserImportLookbackDays,
        &error);
    if (domains.isEmpty()) {
        QMessageBox::warning(
            this,
            QStringLiteral("Import Failed"),
            error.isEmpty()
                ? QStringLiteral("No usable domains were found in the selected browser profile for the last %1 days.").arg(browserImportLookbackDays)
                : error);
        return;
    }

    m_domainsEditor->setPlainText(domains.join(QLatin1Char('\n')));
    appendLogLine(QStringLiteral("Imported %1 browser site(s) from %2, using the last %3 days.")
        .arg(domains.size())
        .arg(sources.at(selectedIndex).label())
        .arg(browserImportLookbackDays));
    QMessageBox::information(
        this,
        QStringLiteral("Sites Imported"),
        QStringLiteral("Imported %1 normalized domain(s) from %2.\n\nThe Sites list will be saved with your settings.")
            .arg(domains.size())
            .arg(sources.at(selectedIndex).label()));
}

void MainWindow::resetTestSites()
{
    m_domainsEditor->setPlainText(defaultDomains().join(QLatin1Char('\n')));
    appendLogLine(QStringLiteral("Restored bundled test site list."));
}

void MainWindow::showResolverContextMenu(const QPoint& position)
{
    const QModelIndex proxyIndex = m_table->indexAt(position);
    if (!proxyIndex.isValid()) {
        return;
    }
    if (!m_table->selectionModel()->isSelected(proxyIndex)) {
        m_table->selectionModel()->select(proxyIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    const QModelIndex sourceIndex = m_proxy->mapToSource(proxyIndex);
    const QModelIndex addressIndex = m_model.index(sourceIndex.row(), ResolverModel::AddressColumn);
    const QModelIndex nameIndex = m_model.index(sourceIndex.row(), ResolverModel::DisplayNameColumn);
    const QString address = addressIndex.data(Qt::DisplayRole).toString();
    const QString name = nameIndex.data(Qt::DisplayRole).toString();
    const QString cellText = sourceIndex.data(Qt::DisplayRole).toString();
    const QList<ResolverEntry> entries = m_model.entries();
    if (sourceIndex.row() < 0 || sourceIndex.row() >= entries.size()) {
        return;
    }
    const ResolverEntry entry = entries.at(sourceIndex.row());
    QList<ResolverEntry> selectedEntries;
    const QModelIndexList selectedRows = m_table->selectionModel()->selectedRows();
    selectedEntries.reserve(selectedRows.size());
    QSet<QString> selectedIds;
    for (const QModelIndex& selectedProxyRow : selectedRows) {
        const QModelIndex selectedSourceIndex = m_proxy->mapToSource(selectedProxyRow);
        if (!selectedSourceIndex.isValid()
            || selectedSourceIndex.row() < 0
            || selectedSourceIndex.row() >= entries.size()) {
            continue;
        }
        const ResolverEntry selectedEntry = entries.at(selectedSourceIndex.row());
        if (selectedIds.contains(selectedEntry.id)) {
            continue;
        }
        selectedIds.insert(selectedEntry.id);
        selectedEntries.push_back(selectedEntry);
    }
    if (selectedEntries.isEmpty()) {
        selectedEntries.push_back(entry);
    }

    QMenu menu(this);
    QAction* benchmarkAction = menu.addAction(selectedEntries.size() > 1
            ? QStringLiteral("Benchmark Selected Resolvers (%1)").arg(selectedEntries.size())
            : QStringLiteral("Benchmark This Resolver"),
        this,
        [this, selectedEntries]() {
            startBenchmarkForResolvers(selectedEntries);
    });
    benchmarkAction->setEnabled(!m_controller.isRunning());
    menu.addAction(QStringLiteral("Resolver Details"), this, [this, row = sourceIndex.row()]() {
        const QModelIndex detailIndex = m_model.index(row, ResolverModel::DisplayNameColumn);
        if (detailIndex.isValid()) {
            showResolverDetailsForIndex(m_proxy->mapFromSource(detailIndex));
        }
    });
    const int selectedRowCount = selectedEntries.size();
    QAction* removeAction = menu.addAction(selectedRowCount > 1
            ? QStringLiteral("Remove Selected Resolvers (%1)").arg(selectedRowCount)
            : QStringLiteral("Remove Resolver"),
        this,
        [this]() {
            removeSelectedResolvers();
    });
    removeAction->setEnabled(!m_controller.isRunning());
    menu.addSeparator();
    menu.addAction(QStringLiteral("Copy Address"), this, [address]() {
        QApplication::clipboard()->setText(address);
    });
    menu.addAction(QStringLiteral("Copy Display Name"), this, [name]() {
        QApplication::clipboard()->setText(name);
    });
    menu.addAction(QStringLiteral("Copy Cell"), this, [cellText]() {
        QApplication::clipboard()->setText(cellText);
    });
    menu.exec(m_table->viewport()->mapToGlobal(position));
}

void MainWindow::removeSelectedResolvers()
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before removing resolvers."));
        return;
    }

    QModelIndexList selectedRows = m_table->selectionModel()->selectedRows();
    if (selectedRows.isEmpty()) {
        return;
    }

    if (selectedRows.size() > 1) {
        const QMessageBox::StandardButton answer = QMessageBox::question(
            this,
            QStringLiteral("Remove Resolvers"),
            QStringLiteral("Remove %1 selected resolvers?").arg(selectedRows.size()));
        if (answer != QMessageBox::Yes) {
            return;
        }
    }

    QModelIndexList sourceRows;
    sourceRows.reserve(selectedRows.size());
    const QList<ResolverEntry> currentEntries = m_model.entries();
    for (const QModelIndex& proxyRow : std::as_const(selectedRows)) {
        const QModelIndex sourceIndex = m_proxy->mapToSource(proxyRow);
        if (!sourceIndex.isValid()) {
            continue;
        }
        if (sourceIndex.row() >= 0 && sourceIndex.row() < currentEntries.size()
            && currentEntries.at(sourceIndex.row()).builtInResolver) {
            m_hiddenBuiltInResolverIds.insert(currentEntries.at(sourceIndex.row()).id);
        }
        sourceRows.push_back(sourceIndex);
    }

    m_model.removeRowsByIndexes(sourceRows);
}

void MainWindow::openTimelineForIndex(const QModelIndex& proxyIndex)
{
    if (!proxyIndex.isValid() || proxyIndex.column() != ResolverModel::TimelineColumn) {
        return;
    }

    const QModelIndex sourceIndex = m_proxy->mapToSource(proxyIndex);
    const QList<ResolverEntry> entries = m_model.entries();
    if (sourceIndex.row() < 0 || sourceIndex.row() >= entries.size()) {
        return;
    }
    openTimelineChartDialog(this, entries.at(sourceIndex.row()));
}

void MainWindow::showResolverDetailsForIndex(const QModelIndex& proxyIndex)
{
    if (!proxyIndex.isValid()) {
        return;
    }

    const QModelIndex sourceIndex = m_proxy->mapToSource(proxyIndex);
    const QList<ResolverEntry> entries = m_model.entries();
    if (sourceIndex.row() < 0 || sourceIndex.row() >= entries.size()) {
        return;
    }

    const ResolverEntry entry = entries.at(sourceIndex.row());
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("%1 Details").arg(entry.effectiveName()));
    dialog->resize(760, 560);

    QString details;
    QTextStream stream(&details);
    stream << "Name: " << entry.effectiveName() << '\n';
    stream << "Address: " << entry.address << '\n';
    stream << "Protocol: " << protocolToString(entry.protocol) << '\n';
    stream << resolverPortDetailsLine(entry) << '\n';
    if (!entry.providerFamily.isEmpty()) {
        stream << "Provider: " << entry.providerFamily << '\n';
    }
    if (!entry.resolverNotes.isEmpty()) {
        stream << "Notes: " << entry.resolverNotes << '\n';
    }
    stream << "Verdict: " << resolverVerdict(entry) << '\n';
    stream << "DNSSEC AD: " << (entry.dnssecAuthenticatedDataSeen ? QStringLiteral("seen") : QStringLiteral("not seen")) << "\n\n";

    if (entry.stats.hasSamples()) {
        stream << "Cached stats\n";
        stream << "  Median: " << QString::number(entry.stats.medianMs, 'f', 1) << " ms\n";
        stream << "  P90: " << QString::number(entry.stats.p90Ms, 'f', 1) << " ms\n";
        stream << "  Mean: " << QString::number(entry.stats.meanMs, 'f', 1) << " ms\n";
        stream << "  Stddev: " << QString::number(entry.stats.stddevMs, 'f', 1) << " ms\n";
        stream << "  Min/Max: " << QString::number(entry.stats.minMs, 'f', 1) << " / " << QString::number(entry.stats.maxMs, 'f', 1) << " ms\n";
        stream << "  Loss: " << QString::number(entry.stats.lossPercent, 'f', 1) << "%\n\n";
    }
    if (entry.uncachedStats.totalCount > 0) {
        stream << "Uncached stats\n";
        stream << "  Median: " << QString::number(entry.uncachedStats.medianMs, 'f', 1) << " ms\n";
        stream << "  P90: " << QString::number(entry.uncachedStats.p90Ms, 'f', 1) << " ms\n";
        stream << "  Mean: " << QString::number(entry.uncachedStats.meanMs, 'f', 1) << " ms\n";
        stream << "  Stddev: " << QString::number(entry.uncachedStats.stddevMs, 'f', 1) << " ms\n";
        stream << "  Min/Max: " << QString::number(entry.uncachedStats.minMs, 'f', 1) << " / " << QString::number(entry.uncachedStats.maxMs, 'f', 1) << " ms\n";
        stream << "  Loss: " << QString::number(entry.uncachedStats.lossPercent, 'f', 1) << "%\n\n";
    }

    int failures = 0;
    int outliers = 0;
    double outlierThreshold = 0.0;
    if (entry.stats.hasSamples()) {
        outlierThreshold = std::max(entry.stats.p90Ms * 2.0, entry.stats.medianMs + 20.0);
    }

    stream << "Samples\n";
    if (outlierThreshold > 0) {
        stream << "  Outlier threshold: >= " << QString::number(outlierThreshold, 'f', 1) << " ms\n";
    }

    QHash<QString, int> failureCounts;
    QVector<ResolverSamplePoint> notableSamples;
    constexpr int maxNotableSamples = 24;
    for (const ResolverSamplePoint& sample : entry.samples) {
        if (!sample.success) {
            ++failures;
            const QString reason = sample.errorString.isEmpty() ? QStringLiteral("failed") : sample.errorString;
            ++failureCounts[reason];
            if (notableSamples.size() < maxNotableSamples) {
                notableSamples.push_back(sample);
            }
            continue;
        }
        if (outlierThreshold > 0 && sample.rttMs >= outlierThreshold) {
            ++outliers;
            if (notableSamples.size() < maxNotableSamples) {
                notableSamples.push_back(sample);
            }
        }
    }

    if (entry.samples.isEmpty()) {
        stream << "  No sample timeline recorded.\n";
    } else {
        stream << "  Failed samples: " << failures << " / " << entry.samples.size() << '\n';
        stream << "  Latency outliers: " << outliers << " / " << entry.samples.size() << '\n';

        if (!failureCounts.isEmpty()) {
            QStringList reasons = failureCounts.keys();
            std::sort(reasons.begin(), reasons.end(), [&failureCounts](const QString& left, const QString& right) {
                if (failureCounts.value(left) != failureCounts.value(right)) {
                    return failureCounts.value(left) > failureCounts.value(right);
                }
                return left < right;
            });

            stream << "\nFailure reasons\n";
            for (const QString& reason : reasons) {
                stream << "  " << failureCounts.value(reason) << "x " << reason << '\n';
            }
        }

        if (entry.passSamples.size() > 1) {
            stream << "\nPass summary\n";
            for (int pass = 0; pass < entry.passSamples.size(); ++pass) {
                int passFailures = 0;
                int passOutliers = 0;
                for (const ResolverSamplePoint& sample : entry.passSamples.at(pass)) {
                    if (!sample.success) {
                        ++passFailures;
                    } else if (outlierThreshold > 0 && sample.rttMs >= outlierThreshold) {
                        ++passOutliers;
                    }
                }
                stream << "  Pass " << (pass + 1) << ": " << passFailures << " failed, " << passOutliers << " outliers\n";
            }
        }

        if (!notableSamples.isEmpty()) {
            stream << "\nNotable samples";
            if (notableSamples.size() < failures + outliers) {
                stream << " (first " << notableSamples.size() << " of " << (failures + outliers) << ')';
            }
            stream << '\n';
            for (const ResolverSamplePoint& sample : notableSamples) {
                stream << "  ";
                if (entry.passSamples.size() > 1) {
                    stream << "pass " << (sample.passIndex + 1) << ", ";
                }
                stream << "#" << (sample.sampleIndex + 1) << ": ";
                if (!sample.success) {
                    stream << "failed";
                    if (!sample.errorString.isEmpty()) {
                        stream << " - " << sample.errorString;
                    }
                } else {
                    stream << QString::number(sample.rttMs, 'f', 1) << " ms outlier";
                }
                stream << '\n';
            }
        } else {
            stream << "  No failed samples or latency outliers recorded.\n";
        }
    }

    auto* editor = new QPlainTextEdit(dialog);
    editor->setReadOnly(true);
    editor->setLineWrapMode(QPlainTextEdit::NoWrap);
    editor->setPlainText(details);

    auto* layout = new QVBoxLayout(dialog);
    layout->addWidget(editor);
    dialog->show();
}

void MainWindow::queueResolverFinished(const QString& resolverId, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples, const Statistics& uncachedStats, const QVector<ResolverSamplePoint>& uncachedSamples)
{
    m_pendingResolverUpdates.insert(resolverId, PendingResolverUpdate{stats, status, dnssecAuthenticatedDataSeen, samples, uncachedStats, uncachedSamples});
    const bool terminalStatus = status == ResolverStatus::Finished
        || status == ResolverStatus::Sidelined
        || status == ResolverStatus::Failed;
    if (m_requestedPasses > 1 && terminalStatus) {
        const int passIndex = std::max(0, m_currentPass - 1);
        auto setPassValue = [passIndex](auto* values, const auto& value) {
            if (values->size() <= passIndex) {
                values->resize(passIndex + 1);
            }
            (*values)[passIndex] = value;
        };
        QVector<ResolverSamplePoint> passSamples = samples;
        for (ResolverSamplePoint& sample : passSamples) {
            sample.passIndex = passIndex;
        }
        setPassValue(&m_repeatPassSamples[resolverId], passSamples);
        setPassValue(&m_repeatPassStats[resolverId], stats);
        setPassValue(&m_repeatPassStatuses[resolverId], status);
        m_repeatDnssecSeen[resolverId] = m_repeatDnssecSeen.value(resolverId, false) || dnssecAuthenticatedDataSeen;
        if (uncachedStats.totalCount > 0 || !uncachedSamples.isEmpty()) {
            QVector<ResolverSamplePoint> passUncachedSamples = uncachedSamples;
            for (ResolverSamplePoint& sample : passUncachedSamples) {
                sample.passIndex = passIndex;
            }
            setPassValue(&m_repeatUncachedPassSamples[resolverId], passUncachedSamples);
            setPassValue(&m_repeatUncachedPassStats[resolverId], uncachedStats);
        }
    }
    if (!m_modelFlushTimer->isActive()) {
        m_modelFlushTimer->start();
    }
}

void MainWindow::queueResolverStatus(const QString& resolverId, ResolverStatus status)
{
    m_pendingStatusUpdates.insert(resolverId, status);
    if (!m_modelFlushTimer->isActive()) {
        m_modelFlushTimer->start();
    }
}

void MainWindow::flushPendingModelUpdates()
{
    if (m_pendingStatusUpdates.isEmpty() && m_pendingResolverUpdates.isEmpty()) {
        m_modelFlushTimer->stop();
        return;
    }

    int processed = 0;
    const QStringList statusKeys = m_pendingStatusUpdates.keys();
    for (const QString& resolverId : statusKeys) {
        if (processed >= maxModelUpdatesPerFlush) {
            break;
        }
        const auto it = m_pendingStatusUpdates.constFind(resolverId);
        if (it == m_pendingStatusUpdates.cend()) {
            continue;
        }
        if (m_pendingResolverUpdates.contains(resolverId)) {
            m_pendingStatusUpdates.remove(resolverId);
            continue;
        }
        const ResolverStatus status = it.value();
        m_pendingStatusUpdates.remove(resolverId);
        m_model.updateStatus(resolverId, status);
        ++processed;
    }

    const QStringList resolverKeys = m_pendingResolverUpdates.keys();
    for (const QString& resolverId : resolverKeys) {
        if (processed >= maxModelUpdatesPerFlush) {
            break;
        }
        const auto it = m_pendingResolverUpdates.constFind(resolverId);
        if (it == m_pendingResolverUpdates.cend()) {
            continue;
        }
        const PendingResolverUpdate update = it.value();
        m_pendingResolverUpdates.remove(resolverId);
        m_model.updateStats(resolverId, update.stats, update.status, update.dnssecAuthenticatedDataSeen, update.samples, {update.samples}, update.uncachedStats, update.uncachedSamples, update.uncachedSamples.isEmpty() ? QVector<QVector<ResolverSamplePoint>>() : QVector<QVector<ResolverSamplePoint>>{update.uncachedSamples});
        ++processed;
    }

    if (processed > 0) {
        m_proxy->sort(m_table->horizontalHeader()->sortIndicatorSection(), m_table->horizontalHeader()->sortIndicatorOrder());
    }

    if (m_pendingStatusUpdates.isEmpty() && m_pendingResolverUpdates.isEmpty()) {
        m_modelFlushTimer->stop();
    } else if (!m_modelFlushTimer->isActive()) {
        m_modelFlushTimer->start();
    }
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
    QList<ResolverEntry> reliableFinished;
    QList<ResolverEntry> sidelined;
    ResolverEntry stable;
    ResolverEntry system;
    bool hasStable = false;
    bool hasSystem = false;
    int dohTotal = 0;
    int dohFinished = 0;
    QStringList unreliable;
    QStringList latencyOutliers;
    QStringList dnssecAdSeen;

    for (const ResolverEntry& entry : entries) {
        if (!m_currentRunIds.isEmpty() && !m_currentRunIds.contains(entry.id)) {
            continue;
        }
        if (entry.protocol == ResolverProtocol::DoH && entry.enabled) {
            ++dohTotal;
        }
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
        if (entry.protocol == ResolverProtocol::DoH) {
            ++dohFinished;
        }
        finished.push_back(entry);
        if (isReliableResult(entry)) {
            reliableFinished.push_back(entry);
        }
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
        if (resolverHasLatencyOutliers(entry)) {
            latencyOutliers.push_back(QStringLiteral("%1 (max %2 ms)").arg(entry.effectiveName()).arg(entry.stats.maxMs, 0, 'f', 1));
        }
        if (entry.dnssecAuthenticatedDataSeen) {
            dnssecAdSeen.push_back(entry.effectiveName());
        }
    }

    std::sort(finished.begin(), finished.end(), resultLessThan);
    std::sort(reliableFinished.begin(), reliableFinished.end(), resultLessThan);

    QStringList lines;
    if (!reliableFinished.isEmpty()) {
        const ResolverEntry& recommended = reliableFinished.first();
        lines << QStringLiteral("Fastest reliable resolver: %1, median %2 ms, p90 %3 ms, mean %4 ms.")
                     .arg(recommended.effectiveName())
                     .arg(recommended.stats.medianMs, 0, 'f', 1)
                     .arg(recommended.stats.p90Ms, 0, 'f', 1)
                     .arg(recommended.stats.meanMs, 0, 'f', 1);
    } else if (!finished.isEmpty()) {
        lines << QStringLiteral("No reliable resolver completed the benchmark; all finished resolvers had >1% loss.");
    }
    if (hasStable) {
        lines << QStringLiteral("Most stable resolver: %1, stddev %2 ms.").arg(stable.effectiveName()).arg(stable.stats.stddevMs, 0, 'f', 1);
    }
    if (!unreliable.isEmpty()) {
        lines << QStringLiteral("Resolvers with packet loss: %1.").arg(unreliable.join(QStringLiteral(", ")));
    }
    if (!latencyOutliers.isEmpty()) {
        lines << QStringLiteral("Resolvers with latency outliers but no packet loss: %1.").arg(latencyOutliers.join(QStringLiteral(", ")));
    }
    if (!dnssecAdSeen.isEmpty()) {
        lines << QStringLiteral("DNSSEC AD bit observed from: %1.").arg(dnssecAdSeen.join(QStringLiteral(", ")));
    }
    if (hasSystem && system.status == ResolverStatus::Finished && !reliableFinished.isEmpty()) {
        const ResolverEntry& recommended = reliableFinished.first();
        if (system.id == recommended.id) {
            lines << QStringLiteral("System DNS is the fastest reliable measured resolver.");
        } else {
            lines << QStringLiteral("System DNS is %1 ms slower than the fastest reliable alternative.")
                         .arg(system.stats.medianMs - recommended.stats.medianMs, 0, 'f', 1);
        }
    } else if (hasSystem && system.status == ResolverStatus::Sidelined) {
        lines << QStringLiteral("System DNS was sidelined during warm-up; it did not answer at least 3 of 10 reachability probes.");
    }

    if (!reliableFinished.isEmpty()) {
        QStringList top;
        const int topCount = std::min(5, static_cast<int>(reliableFinished.size()));
        for (int i = 0; i < topCount; ++i) {
            const ResolverEntry& entry = reliableFinished.at(i);
            top << QStringLiteral("%1. %2: median %3 ms, p90 %4 ms, mean %5 ms")
                       .arg(i + 1)
                       .arg(entry.effectiveName())
                       .arg(entry.stats.medianMs, 0, 'f', 1)
                       .arg(entry.stats.p90Ms, 0, 'f', 1)
                       .arg(entry.stats.meanMs, 0, 'f', 1);
        }
        lines << QStringLiteral("Top reliable performers:\n%1").arg(top.join(QStringLiteral("\n")));
    }

    QStringList consistencyLines;
    for (const ResolverEntry& entry : reliableFinished) {
        const QVector<Statistics> passStats = m_repeatPassStats.value(entry.id);
        if (passStats.size() < 2) {
            continue;
        }
        double minMedian = std::numeric_limits<double>::max();
        double maxMedian = 0.0;
        double maxLoss = 0.0;
        for (const Statistics& stats : passStats) {
            minMedian = std::min(minMedian, stats.medianMs);
            maxMedian = std::max(maxMedian, stats.medianMs);
            maxLoss = std::max(maxLoss, stats.lossPercent);
        }
        consistencyLines << QStringLiteral("%1: median spread %2 ms across %3 passes, max loss %4%")
                                .arg(entry.effectiveName())
                                .arg(maxMedian - minMedian, 0, 'f', 1)
                                .arg(passStats.size())
                                .arg(maxLoss, 0, 'f', 1);
        if (consistencyLines.size() >= 5) {
            break;
        }
    }
    if (!consistencyLines.isEmpty()) {
        lines << QStringLiteral("Repeat-run consistency:\n%1").arg(consistencyLines.join(QStringLiteral("\n")));
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

    if (dohTotal > 0 && dohFinished == 0) {
        lines << QStringLiteral("All enabled DoH resolvers failed warm-up. Check whether HTTPS/443 to DoH providers is blocked by the network, firewall, or DNS policy.");
    }

    const QString summary = lines.isEmpty() ? QStringLiteral("No completed resolver results.") : lines.join(QStringLiteral("\n"));
    m_resultsTab->setResults(summary, entries);
}

void MainWindow::applyBenchmarkProfile(int profileId)
{
    const auto profile = static_cast<BenchmarkProfile>(profileId);
    if (profile == BenchmarkProfile::Custom) {
        return;
    }

    const BenchmarkProfileSettings profileSettings = settingsForProfile(profile);
    const QSignalBlocker delayBlocker(m_delaySpin);
    m_delaySpin->setValue(profileSettings.delayMs);
}

void MainWindow::markBenchmarkProfileCustom()
{
    if (!m_benchmarkProfileCombo) {
        return;
    }
    const int customProfile = static_cast<int>(BenchmarkProfile::Custom);
    if (m_benchmarkProfileCombo->currentData().toInt() == customProfile) {
        return;
    }

    const QSignalBlocker profileBlocker(m_benchmarkProfileCombo);
    const int customIndex = m_benchmarkProfileCombo->findData(customProfile);
    if (customIndex >= 0) {
        m_benchmarkProfileCombo->setCurrentIndex(customIndex);
    }
}

void MainWindow::loadSettings()
{
    QSettings settings;
    const BenchmarkProfileSettings wiredSettings = settingsForProfile(BenchmarkProfile::WiredLan);
    if (!settings.value(QStringLiteral("benchmark/defaultsV2Applied"), false).toBool()) {
        if (settings.value(QStringLiteral("benchmark/interQueryDelayMs"), 50).toInt() == 50) {
            settings.setValue(QStringLiteral("benchmark/interQueryDelayMs"), wiredSettings.delayMs);
        }
        settings.setValue(QStringLiteral("benchmark/defaultsV2Applied"), true);
    }
    if (!settings.value(QStringLiteral("benchmark/wiredLanDefaultApplied"), false).toBool()) {
        const int currentProfile = settings.value(QStringLiteral("benchmark/profile"), static_cast<int>(BenchmarkProfile::WiredLan)).toInt();
        if (currentProfile == static_cast<int>(BenchmarkProfile::HomeWifi)) {
            settings.setValue(QStringLiteral("benchmark/profile"), static_cast<int>(BenchmarkProfile::WiredLan));
            settings.setValue(QStringLiteral("benchmark/interQueryDelayMs"), wiredSettings.delayMs);
        }
        settings.setValue(QStringLiteral("benchmark/wiredLanDefaultApplied"), true);
    }
    const int savedDelayMs = settings.value(QStringLiteral("benchmark/interQueryDelayMs"), wiredSettings.delayMs).toInt();
    const int profileId = settings.contains(QStringLiteral("benchmark/profile"))
        ? settings.value(QStringLiteral("benchmark/profile")).toInt()
        : static_cast<int>(profileForSettings(savedDelayMs));

    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
    m_sampleSpin->setValue(settings.value(QStringLiteral("benchmark/sampleCount"), 250).toInt());
    m_passSpin->setValue(settings.value(QStringLiteral("benchmark/passes"), 1).toInt());
    const int profileIndex = m_benchmarkProfileCombo->findData(profileId);
    m_benchmarkProfileCombo->setCurrentIndex(profileIndex >= 0 ? profileIndex : m_benchmarkProfileCombo->findData(static_cast<int>(BenchmarkProfile::WiredLan)));
    if (static_cast<BenchmarkProfile>(m_benchmarkProfileCombo->currentData().toInt()) == BenchmarkProfile::Custom) {
        m_delaySpin->setValue(savedDelayMs);
    } else {
        applyBenchmarkProfile(m_benchmarkProfileCombo->currentData().toInt());
    }
    m_ipv4Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv4"), true).toBool());
    m_ipv6Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv6"), true).toBool());
    m_dohToggle->setChecked(settings.value(QStringLiteral("protocols/doh"), true).toBool());
    m_dotToggle->setChecked(settings.value(QStringLiteral("protocols/dot"), true).toBool());
    m_verboseLogToggle->setChecked(settings.value(QStringLiteral("log/verbose"), false).toBool());
    const QString savedDomains = settings.value(QStringLiteral("benchmark/testSites")).toString();
    if (!savedDomains.trimmed().isEmpty()) {
        m_domainsEditor->setPlainText(savedDomains);
    }
    const int resultFilter = settings.value(QStringLiteral("results/filter"), static_cast<int>(ResultFilter::All)).toInt();
    const int resultFilterIndex = m_resultFilterCombo->findData(resultFilter);
    m_resultFilterCombo->setCurrentIndex(resultFilterIndex >= 0 ? resultFilterIndex : 0);
    const QStringList hiddenBuiltIns = settings.value(QStringLiteral("resolvers/hiddenBuiltIns")).toStringList();
    m_hiddenBuiltInResolverIds = QSet<QString>(hiddenBuiltIns.cbegin(), hiddenBuiltIns.cend());

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
    settings.setValue(QStringLiteral("benchmark/passes"), m_passSpin->value());
    settings.setValue(QStringLiteral("benchmark/profile"), m_benchmarkProfileCombo->currentData().toInt());
    settings.setValue(QStringLiteral("benchmark/interQueryDelayMs"), m_delaySpin->value());
    settings.setValue(QStringLiteral("protocols/ipv4"), m_ipv4Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/ipv6"), m_ipv6Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/doh"), m_dohToggle->isChecked());
    settings.setValue(QStringLiteral("protocols/dot"), m_dotToggle->isChecked());
    settings.setValue(QStringLiteral("log/verbose"), m_verboseLogToggle->isChecked());
    settings.setValue(QStringLiteral("benchmark/testSites"), m_domainsEditor->toPlainText());
    settings.setValue(QStringLiteral("results/filter"), m_resultFilterCombo->currentData().toInt());
    settings.setValue(QStringLiteral("resolvers/hiddenBuiltIns"), QStringList(m_hiddenBuiltInResolverIds.cbegin(), m_hiddenBuiltInResolverIds.cend()));

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

QStringList MainWindow::defaultDomains() const
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

QStringList MainWindow::loadDomains() const
{
    QStringList domains;
    const QStringList lines = m_domainsEditor->toPlainText().split(QLatin1Char('\n'));
    for (QString line : lines) {
        const int comment = line.indexOf(QLatin1Char('#'));
        if (comment >= 0) {
            line = line.left(comment);
        }
        line = line.trimmed();
        if (!line.isEmpty()) {
            domains.push_back(line);
        }
    }

    if (domains.isEmpty()) {
        return defaultDomains();
    }
    return domains;
}
