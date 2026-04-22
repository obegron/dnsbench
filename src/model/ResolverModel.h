#pragma once

#include "model/ResolverEntry.h"

#include <QAbstractTableModel>
#include <QList>

class ResolverModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        PinColumn = 0,
        DisplayNameColumn,
        AddressColumn,
        ProtocolColumn,
        MedianColumn,
        P90Column,
        MeanColumn,
        StddevColumn,
        MinColumn,
        MaxColumn,
        LossColumn,
        DnssecColumn,
        StatusColumn,
        ColumnCount
    };

    explicit ResolverModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    Qt::ItemFlags flags(const QModelIndex& index) const override;
    bool setData(const QModelIndex& index, const QVariant& value, int role = Qt::EditRole) override;

    void addResolver(const ResolverEntry& entry);
    void addResolvers(const QList<ResolverEntry>& entries, bool prepend = false);
    void clear();
    void removeRowsByIndexes(const QModelIndexList& indexes);
    void updateStats(const QString& id, const Statistics& stats, ResolverStatus status = ResolverStatus::Finished, bool dnssecAuthenticatedDataSeen = false, const QVector<ResolverSamplePoint>& samples = {});
    void updateStatus(const QString& id, ResolverStatus status);
    void setResolverEnabled(const QString& id, bool enabled);
    void setProtocolEnabled(ResolverProtocol protocol, bool enabled);
    void resetRuntimeState();
    void resetRuntimeState(const QString& id);

    QList<ResolverEntry> entries() const;
    QList<ResolverEntry> enabledEntries() const;
    ResolverEntry* findMutable(const QString& id);
    const ResolverEntry* find(const QString& id) const;

    static QString makeId(const ResolverEntry& entry);

signals:
    void resolverChanged(const ResolverEntry& entry);

private:
    QList<ResolverEntry> m_entries;

    int rowForId(const QString& id) const;
    QVariant statData(const Statistics& stats, Column column, int role) const;
};
