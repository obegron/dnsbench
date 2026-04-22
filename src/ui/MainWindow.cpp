#include "ui/MainWindow.h"

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
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QKeySequence>
#include <QLabel>
#include <QMenuBar>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
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
#include <QTextBrowser>
#include <QTextDocument>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>

namespace {

constexpr int renderedMarkdownRowLimit = 250;

class PinnedSortProxyModel : public QSortFilterProxyModel {
public:
    using QSortFilterProxyModel::QSortFilterProxyModel;

protected:
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
            return left.data(Qt::UserRole).toDouble() < right.data(Qt::UserRole).toDouble();
        case ResolverModel::TimelineColumn:
            return left.sibling(left.row(), ResolverModel::MedianColumn).data(Qt::UserRole).toDouble()
                < right.sibling(right.row(), ResolverModel::MedianColumn).data(Qt::UserRole).toDouble();
        case ResolverModel::ColumnCount:
            break;
        }
        return false;
    }

private:
    int sortRank(int sourceRow) const
    {
        const auto status = static_cast<ResolverStatus>(sourceModel()->index(sourceRow, ResolverModel::StatusColumn).data(Qt::UserRole).toInt());
        switch (status) {
        case ResolverStatus::Finished:
            return 0;
        case ResolverStatus::Running:
            return 1;
        case ResolverStatus::Sidelined:
        case ResolverStatus::Failed:
            return 2;
        case ResolverStatus::Idle:
        case ResolverStatus::Disabled:
            return 3;
        }
        return 3;
    }
};

class LatencyBarDelegate : public QStyledItemDelegate {
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
    {
        const auto status = static_cast<ResolverStatus>(index.sibling(index.row(), ResolverModel::StatusColumn).data(Qt::UserRole).toInt());
        if (status != ResolverStatus::Finished) {
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
                maxRtt = std::max(maxRtt, static_cast<qreal>(std::max<qint64>(1, sample.rttMs)));
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
        if (!url.isValid() || url.host().isEmpty()) {
            if (reason) {
                *reason = QStringLiteral("invalid DoH URL or host");
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
    return entry.stats.lossPercent <= 1.0;
}

bool resultLessThan(const ResolverEntry& left, const ResolverEntry& right)
{
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
    if (left.stats.p90Ms != right.stats.p90Ms) {
        return left.stats.p90Ms < right.stats.p90Ms;
    }
    return left.stats.meanMs < right.stats.meanMs;
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

    auto* tabs = new QTabWidget(this);
    tabs->addTab(m_resultsTab, QStringLiteral("Results"));
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
    QAction* importAction = toolbar->addAction(QStringLiteral("Import"), this, &MainWindow::importResolvers);
    importAction->setToolTip(QStringLiteral("Import resolvers from CSV, TSV, Markdown, JSON, or one resolver per line."));
    toolbar->addAction(QStringLiteral("Detect System DNS"), this, &MainWindow::detectSystemDns);
    toolbar->addAction(QStringLiteral("Restore Built-ins"), this, &MainWindow::restoreBuiltInResolvers);
    toolbar->addAction(QStringLiteral("Export"), this, &MainWindow::exportResults);
    toolbar->addAction(QStringLiteral("Copy Results"), this, &MainWindow::cloneResults);
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
    m_verboseLogToggle = new QCheckBox(QStringLiteral("Verbose Log"), this);
    m_verboseLogToggle->setToolTip(QStringLiteral("Log every query and response. Leave off for smoother large benchmarks."));
    toolbar->addWidget(m_verboseLogToggle);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Samples"), this));
    m_sampleSpin = new QSpinBox(this);
    m_sampleSpin->setRange(1, 25000);
    m_sampleSpin->setValue(250);
    toolbar->addWidget(m_sampleSpin);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Delay"), this));
    m_delaySpin = new QSpinBox(this);
    m_delaySpin->setRange(0, 5000);
    m_delaySpin->setValue(50);
    m_delaySpin->setSuffix(QStringLiteral(" ms"));
    m_delaySpin->setToolTip(QStringLiteral("Delay between queries sent by each resolver."));
    toolbar->addWidget(m_delaySpin);

    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(QStringLiteral("Concurrent"), this));
    m_concurrencySpin = new QSpinBox(this);
    m_concurrencySpin->setRange(1, 500);
    m_concurrencySpin->setValue(20);
    m_concurrencySpin->setToolTip(QStringLiteral("Maximum number of resolvers benchmarked at the same time. Higher values finish large lists faster but can add network or resolver rate-limit noise."));
    toolbar->addWidget(m_concurrencySpin);

    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 100);
    m_progress->setValue(0);
    m_etaLabel = new QLabel(QStringLiteral("0/0 queries | ETA: -"), this);
    statusBar()->addPermanentWidget(m_etaLabel);
    statusBar()->addPermanentWidget(m_progress, 1);

    menuBar()->hide();
}

void MainWindow::connectController()
{
    connect(&m_controller, &BenchmarkController::progressUpdated, this, &MainWindow::updateProgress);
    connect(&m_controller, &BenchmarkController::resolverFinished, this, [this](const QString& resolverId, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples) {
        m_model.updateStats(resolverId, stats, status, dnssecAuthenticatedDataSeen, samples);
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
    m_currentRunIds.clear();
    for (const ResolverEntry& entry : runEntries) {
        m_currentRunIds.insert(entry.id);
    }

    m_model.resetRuntimeState();
    m_progress->setValue(0);
    m_resultsTab->setSummary(QStringLiteral("Benchmark running..."));
    appendLogLine(QStringLiteral("Starting benchmark."));
    m_controller.setVerboseLogging(m_verboseLogToggle->isChecked());
    m_controller.setMaxConcurrentResolvers(m_concurrencySpin->value());
    m_controller.start(runEntries, m_sampleSpin->value(), m_delaySpin->value(), loadDomains());
}

void MainWindow::startBenchmarkForResolver(const ResolverEntry& entry)
{
    if (m_controller.isRunning()) {
        QMessageBox::information(this, QStringLiteral("Benchmark Running"), QStringLiteral("Stop the current benchmark before starting another one."));
        return;
    }

    ResolverEntry runEntry = entry;
    runEntry.enabled = true;
    m_model.setResolverEnabled(runEntry.id, true);
    m_model.resetRuntimeState(runEntry.id);
    m_currentRunIds = {runEntry.id};
    m_progress->setValue(0);
    m_resultsTab->setSummary(QStringLiteral("Benchmark running for %1...").arg(runEntry.effectiveName()));
    appendLogLine(QStringLiteral("Starting single-resolver benchmark for %1.").arg(runEntry.effectiveName()));
    m_controller.setVerboseLogging(m_verboseLogToggle->isChecked());
    m_controller.setMaxConcurrentResolvers(m_concurrencySpin->value());
    m_controller.start({runEntry}, m_sampleSpin->value(), m_delaySpin->value(), loadDomains());
}

void MainWindow::stopBenchmark()
{
    m_controller.stop();
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

    QMenu menu(this);
    menu.addAction(QStringLiteral("Benchmark This Resolver"), this, [this, entry]() {
        startBenchmarkForResolver(entry);
    });
    const int selectedRows = m_table->selectionModel()->selectedRows().size();
    QAction* removeAction = menu.addAction(selectedRows > 1
            ? QStringLiteral("Remove Selected Resolvers (%1)").arg(selectedRows)
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
        lines << QStringLiteral("Resolvers with >1% loss: %1.").arg(unreliable.join(QStringLiteral(", ")));
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

void MainWindow::loadSettings()
{
    QSettings settings;
    restoreGeometry(settings.value(QStringLiteral("window/geometry")).toByteArray());
    m_sampleSpin->setValue(settings.value(QStringLiteral("benchmark/sampleCount"), 250).toInt());
    m_delaySpin->setValue(settings.value(QStringLiteral("benchmark/interQueryDelayMs"), 50).toInt());
    m_concurrencySpin->setValue(settings.value(QStringLiteral("benchmark/maxConcurrentResolvers"), 20).toInt());
    m_ipv4Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv4"), true).toBool());
    m_ipv6Toggle->setChecked(settings.value(QStringLiteral("protocols/ipv6"), true).toBool());
    m_dohToggle->setChecked(settings.value(QStringLiteral("protocols/doh"), true).toBool());
    m_dotToggle->setChecked(settings.value(QStringLiteral("protocols/dot"), true).toBool());
    m_verboseLogToggle->setChecked(settings.value(QStringLiteral("log/verbose"), false).toBool());
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
    settings.setValue(QStringLiteral("benchmark/interQueryDelayMs"), m_delaySpin->value());
    settings.setValue(QStringLiteral("benchmark/maxConcurrentResolvers"), m_concurrencySpin->value());
    settings.setValue(QStringLiteral("protocols/ipv4"), m_ipv4Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/ipv6"), m_ipv6Toggle->isChecked());
    settings.setValue(QStringLiteral("protocols/doh"), m_dohToggle->isChecked());
    settings.setValue(QStringLiteral("protocols/dot"), m_dotToggle->isChecked());
    settings.setValue(QStringLiteral("log/verbose"), m_verboseLogToggle->isChecked());
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
