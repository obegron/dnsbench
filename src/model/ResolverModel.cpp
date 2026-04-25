#include "model/ResolverModel.h"

#include <QBrush>
#include <QColor>
#include <QLocale>
#include <QSet>

#include <algorithm>

QString ResolverEntry::effectiveName() const
{
    if (!displayName.trimmed().isEmpty()) {
        return displayName;
    }
    return address;
}

QString protocolToString(ResolverProtocol protocol)
{
    switch (protocol) {
    case ResolverProtocol::IPv4:
        return QStringLiteral("IPv4");
    case ResolverProtocol::IPv6:
        return QStringLiteral("IPv6");
    case ResolverProtocol::DoH:
        return QStringLiteral("DoH");
    case ResolverProtocol::DoT:
        return QStringLiteral("DoT");
    }
    return QStringLiteral("IPv4");
}

QString protocolDisplayString(ResolverProtocol protocol)
{
    switch (protocol) {
    case ResolverProtocol::IPv4:
        return QString::fromUtf8("\xf0\x9f\x8c\x90 IPv4");
    case ResolverProtocol::IPv6:
        return QString::fromUtf8("\xf0\x9f\x8c\x90 IPv6");
    case ResolverProtocol::DoH:
        return QString::fromUtf8("\xf0\x9f\x94\x92 DoH");
    case ResolverProtocol::DoT:
        return QString::fromUtf8("\xf0\x9f\x94\x92 DoT");
    }
    return protocolToString(protocol);
}

ResolverProtocol protocolFromString(const QString& value, bool* ok)
{
    const QString normalized = value.trimmed().toLower();
    if (normalized == QLatin1String("ipv4")) {
        if (ok) {
            *ok = true;
        }
        return ResolverProtocol::IPv4;
    }
    if (normalized == QLatin1String("ipv6")) {
        if (ok) {
            *ok = true;
        }
        return ResolverProtocol::IPv6;
    }
    if (normalized == QLatin1String("doh")) {
        if (ok) {
            *ok = true;
        }
        return ResolverProtocol::DoH;
    }
    if (normalized == QLatin1String("dot")) {
        if (ok) {
            *ok = true;
        }
        return ResolverProtocol::DoT;
    }
    if (ok) {
        *ok = false;
    }
    return ResolverProtocol::IPv4;
}

QString statusToString(ResolverStatus status)
{
    switch (status) {
    case ResolverStatus::Idle:
        return QStringLiteral("Idle");
    case ResolverStatus::Running:
        return QStringLiteral("Running");
    case ResolverStatus::Finished:
        return QStringLiteral("Finished");
    case ResolverStatus::Failed:
        return QStringLiteral("Failed");
    case ResolverStatus::Sidelined:
        return QStringLiteral("Sidelined");
    case ResolverStatus::Disabled:
        return QStringLiteral("Disabled");
    }
    return QStringLiteral("Idle");
}

QString resolverVerdict(const ResolverEntry& entry)
{
    if (!entry.enabled || entry.status == ResolverStatus::Disabled) {
        return statusToString(ResolverStatus::Disabled);
    }
    if (entry.status != ResolverStatus::Finished) {
        return statusToString(entry.status);
    }
    if (!entry.stats.hasSamples()) {
        return QStringLiteral("No result");
    }
    if (entry.stats.lossPercent > 1.0) {
        return QStringLiteral("Unreliable");
    }
    if (entry.stats.stddevMs > std::max(20.0, entry.stats.medianMs * 3.0)) {
        return QStringLiteral("Spiky latency");
    }
    if (entry.stats.medianMs <= 10.0) {
        return QStringLiteral("Very fast");
    }
    if (entry.stats.medianMs <= 25.0) {
        return QStringLiteral("Fast");
    }
    return QStringLiteral("Measured");
}

int defaultPortForProtocol(ResolverProtocol protocol)
{
    switch (protocol) {
    case ResolverProtocol::DoT:
        return 853;
    case ResolverProtocol::IPv4:
    case ResolverProtocol::IPv6:
    case ResolverProtocol::DoH:
        return 53;
    }
    return 53;
}

ResolverModel::ResolverModel(QObject* parent)
    : QAbstractTableModel(parent)
{
}

int ResolverModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : m_entries.size();
}

int ResolverModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ResolverModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_entries.size()) {
        return {};
    }

    const ResolverEntry& entry = m_entries.at(index.row());
    const auto column = static_cast<Column>(index.column());

    if (role == Qt::CheckStateRole && column == PinColumn) {
        return entry.pinned ? Qt::Checked : Qt::Unchecked;
    }

    if (role == Qt::ToolTipRole && column == PinColumn) {
        return QStringLiteral("Pin keeps this resolver at the top while sorting. It does not control benchmark selection.");
    }

    if (role == Qt::ForegroundRole) {
        if (!entry.enabled || entry.status == ResolverStatus::Disabled) {
            return QBrush(QColor(130, 130, 130));
        }
        if (column == DnssecColumn
            && entry.status == ResolverStatus::Finished
            && entry.stats.hasSamples()
            && entry.dnssecAuthenticatedDataSeen) {
            return QBrush(QColor(25, 120, 55));
        }
    }

    if (role == HasSamplesRole) {
        return entry.stats.hasSamples();
    }

    if (role == Qt::UserRole) {
        switch (column) {
        case PinColumn:
            return entry.pinned;
        case ProtocolColumn:
            return static_cast<int>(entry.protocol);
        case MedianColumn:
            return entry.stats.medianMs;
        case P90Column:
            return entry.stats.p90Ms;
        case MeanColumn:
            return entry.stats.meanMs;
        case StddevColumn:
            return entry.stats.stddevMs;
        case MinColumn:
            return entry.stats.minMs;
        case MaxColumn:
            return entry.stats.maxMs;
        case LossColumn:
            return entry.stats.lossPercent;
        case TimelineColumn:
            return QVariant::fromValue(entry.samples);
        case DnssecColumn:
            return entry.dnssecAuthenticatedDataSeen ? 1 : 0;
        case StatusColumn:
            return static_cast<int>(entry.enabled ? entry.status : ResolverStatus::Disabled);
        default:
            break;
        }
    }

    if (role != Qt::DisplayRole && role != Qt::EditRole) {
        return {};
    }

    switch (column) {
    case PinColumn:
        return QString();
    case DisplayNameColumn:
        return entry.effectiveName();
    case AddressColumn:
        return entry.port == defaultPortForProtocol(entry.protocol)
            ? entry.address
            : QStringLiteral("%1:%2").arg(entry.address).arg(entry.port);
    case ProtocolColumn:
        return protocolDisplayString(entry.protocol);
    case MedianColumn:
    case P90Column:
    case MeanColumn:
    case StddevColumn:
    case MinColumn:
    case MaxColumn:
    case LossColumn:
        return statData(entry.stats, column, role);
    case TimelineColumn:
        return QString();
    case DnssecColumn:
        if (entry.status == ResolverStatus::Finished && entry.stats.hasSamples()) {
            return entry.dnssecAuthenticatedDataSeen ? QStringLiteral("AD seen") : QStringLiteral("No AD");
        }
        return QStringLiteral("-");
    case StatusColumn:
        return resolverVerdict(entry);
    case ColumnCount:
        break;
    }

    return {};
}

QVariant ResolverModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation != Qt::Horizontal || role != Qt::DisplayRole) {
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    switch (static_cast<Column>(section)) {
    case PinColumn:
        return QStringLiteral("Pin");
    case DisplayNameColumn:
        return QStringLiteral("Display Name");
    case AddressColumn:
        return QStringLiteral("Address");
    case ProtocolColumn:
        return QStringLiteral("Protocol");
    case MedianColumn:
        return QStringLiteral("Median (ms)");
    case P90Column:
        return QStringLiteral("P90 (ms)");
    case MeanColumn:
        return QStringLiteral("Mean (ms)");
    case StddevColumn:
        return QStringLiteral("Stddev");
    case MinColumn:
        return QStringLiteral("Min");
    case MaxColumn:
        return QStringLiteral("Max");
    case LossColumn:
        return QStringLiteral("Loss (%)");
    case TimelineColumn:
        return QStringLiteral("Timeline");
    case DnssecColumn:
        return QStringLiteral("DNSSEC");
    case StatusColumn:
        return QStringLiteral("Status");
    case ColumnCount:
        break;
    }
    return {};
}

Qt::ItemFlags ResolverModel::flags(const QModelIndex& index) const
{
    if (!index.isValid()) {
        return Qt::NoItemFlags;
    }

    Qt::ItemFlags result = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
    if (index.column() == PinColumn) {
        result |= Qt::ItemIsUserCheckable;
    }
    return result;
}

bool ResolverModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
    if (!index.isValid() || index.row() < 0 || index.row() >= m_entries.size()) {
        return false;
    }

    ResolverEntry& entry = m_entries[index.row()];
    if (index.column() == PinColumn && role == Qt::CheckStateRole) {
        entry.pinned = value.toInt() == Qt::Checked;
        emit dataChanged(index, index, {Qt::CheckStateRole, Qt::DisplayRole, Qt::UserRole});
        emit resolverChanged(entry);
        return true;
    }

    return false;
}

void ResolverModel::addResolver(const ResolverEntry& entry)
{
    ResolverEntry copy = entry;
    if (copy.id.isEmpty()) {
        copy.id = makeId(copy);
    }
    const int row = m_entries.size();
    beginInsertRows({}, row, row);
    m_entries.push_back(copy);
    endInsertRows();
}

void ResolverModel::addResolvers(const QList<ResolverEntry>& entries, bool prepend)
{
    if (entries.isEmpty()) {
        return;
    }

    QList<ResolverEntry> copies;
    copies.reserve(entries.size());
    for (ResolverEntry entry : entries) {
        if (entry.id.isEmpty()) {
            entry.id = makeId(entry);
        }
        copies.push_back(entry);
    }

    const int first = prepend ? 0 : m_entries.size();
    const int last = first + copies.size() - 1;
    beginInsertRows({}, first, last);
    if (prepend) {
        for (auto it = copies.crbegin(); it != copies.crend(); ++it) {
            m_entries.push_front(*it);
        }
    } else {
        m_entries.append(copies);
    }
    endInsertRows();
}

void ResolverModel::clear()
{
    beginResetModel();
    m_entries.clear();
    endResetModel();
}

void ResolverModel::removeRowsByIndexes(const QModelIndexList& indexes)
{
    QSet<int> rows;
    for (const QModelIndex& index : indexes) {
        if (index.isValid()) {
            rows.insert(index.row());
        }
    }

    QList<int> sortedRows = rows.values();
    std::sort(sortedRows.begin(), sortedRows.end(), std::greater<>());
    for (int row : sortedRows) {
        if (row < 0 || row >= m_entries.size()) {
            continue;
        }
        beginRemoveRows({}, row, row);
        m_entries.removeAt(row);
        endRemoveRows();
    }
}

void ResolverModel::updateStats(const QString& id, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples)
{
    const int row = rowForId(id);
    if (row < 0) {
        return;
    }

    m_entries[row].stats = stats;
    m_entries[row].status = status;
    m_entries[row].dnssecAuthenticatedDataSeen = dnssecAuthenticatedDataSeen;
    m_entries[row].samples = samples;
    emit dataChanged(index(row, MedianColumn), index(row, StatusColumn),
        {Qt::DisplayRole, Qt::UserRole, Qt::ForegroundRole, HasSamplesRole});
    emit resolverChanged(m_entries[row]);
}

void ResolverModel::updateStatus(const QString& id, ResolverStatus status)
{
    const int row = rowForId(id);
    if (row < 0) {
        return;
    }

    m_entries[row].status = status;
    emit dataChanged(index(row, StatusColumn), index(row, StatusColumn),
        {Qt::DisplayRole, Qt::UserRole, Qt::ForegroundRole});
    emit resolverChanged(m_entries[row]);
}

void ResolverModel::setResolverEnabled(const QString& id, bool enabled)
{
    const int row = rowForId(id);
    if (row < 0) {
        return;
    }

    m_entries[row].enabled = enabled;
    emit dataChanged(index(row, 0), index(row, ColumnCount - 1));
    emit resolverChanged(m_entries[row]);
}

void ResolverModel::setProtocolEnabled(ResolverProtocol protocol, bool enabled)
{
    bool changed = false;
    for (int row = 0; row < m_entries.size(); ++row) {
        if (m_entries[row].protocol != protocol) {
            continue;
        }
        if (m_entries[row].enabled == enabled) {
            continue;
        }
        m_entries[row].enabled = enabled;
        changed = true;
    }
    if (changed && !m_entries.isEmpty()) {
        emit dataChanged(index(0, 0), index(m_entries.size() - 1, ColumnCount - 1));
    }
}

void ResolverModel::resetRuntimeState()
{
    if (m_entries.isEmpty()) {
        return;
    }

    for (ResolverEntry& entry : m_entries) {
        entry.stats = {};
        entry.status = ResolverStatus::Idle;
        entry.dnssecAuthenticatedDataSeen = false;
        entry.samples.clear();
    }
    emit dataChanged(index(0, 0), index(m_entries.size() - 1, ColumnCount - 1));
}

void ResolverModel::resetRuntimeState(const QString& id)
{
    const int row = rowForId(id);
    if (row < 0) {
        return;
    }

    m_entries[row].stats = {};
    m_entries[row].status = ResolverStatus::Idle;
    m_entries[row].dnssecAuthenticatedDataSeen = false;
    m_entries[row].samples.clear();
    emit dataChanged(index(row, 0), index(row, StatusColumn));
    emit resolverChanged(m_entries[row]);
}

QList<ResolverEntry> ResolverModel::entries() const
{
    return m_entries;
}

QList<ResolverEntry> ResolverModel::enabledEntries() const
{
    QList<ResolverEntry> result;
    for (const ResolverEntry& entry : m_entries) {
        if (entry.enabled) {
            result.push_back(entry);
        }
    }
    return result;
}

ResolverEntry* ResolverModel::findMutable(const QString& id)
{
    for (ResolverEntry& entry : m_entries) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}

const ResolverEntry* ResolverModel::find(const QString& id) const
{
    for (const ResolverEntry& entry : m_entries) {
        if (entry.id == id) {
            return &entry;
        }
    }
    return nullptr;
}

QString ResolverModel::makeId(const ResolverEntry& entry)
{
    return QStringLiteral("%1|%2|%3").arg(protocolToString(entry.protocol), entry.address).arg(entry.port);
}

int ResolverModel::rowForId(const QString& id) const
{
    for (int i = 0; i < m_entries.size(); ++i) {
        if (m_entries.at(i).id == id) {
            return i;
        }
    }
    return -1;
}

QVariant ResolverModel::statData(const Statistics& stats, Column column, int role) const
{
    if (stats.totalCount == 0) {
        return role == Qt::DisplayRole ? QStringLiteral("-") : QVariant();
    }

    const QLocale locale;
    if (stats.successCount == 0) {
        switch (column) {
        case MedianColumn:
        case P90Column:
        case MeanColumn:
        case StddevColumn:
        case MinColumn:
        case MaxColumn:
            return role == Qt::DisplayRole ? QStringLiteral("-") : QVariant();
        case LossColumn:
            return locale.toString(stats.lossPercent, 'f', 1);
        default:
            return {};
        }
    }

    switch (column) {
    case MedianColumn:
        return locale.toString(stats.medianMs, 'f', 1);
    case P90Column:
        return locale.toString(stats.p90Ms, 'f', 1);
    case MeanColumn:
        return locale.toString(stats.meanMs, 'f', 1);
    case StddevColumn:
        return locale.toString(stats.stddevMs, 'f', 1);
    case MinColumn:
        return stats.successCount == 0 ? QStringLiteral("-") : locale.toString(stats.minMs, 'f', 1);
    case MaxColumn:
        return stats.successCount == 0 ? QStringLiteral("-") : locale.toString(stats.maxMs, 'f', 1);
    case LossColumn:
        return locale.toString(stats.lossPercent, 'f', 1);
    default:
        return {};
    }
}
