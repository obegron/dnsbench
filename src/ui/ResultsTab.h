#pragma once

#include "model/ResolverEntry.h"

#include <QList>
#include <QWidget>

class QChartView;
class QChart;
class QComboBox;
class QLabel;
class QPushButton;

class ResultsTab : public QWidget {
    Q_OBJECT

public:
    explicit ResultsTab(QWidget* parent = nullptr);
    void setSummary(const QString& summary);
    void setResults(const QString& summary, const QList<ResolverEntry>& entries);

private:
    QList<ResolverEntry> m_entries;
    QLabel* m_label = nullptr;
    QComboBox* m_resolverPicker = nullptr;
    QPushButton* m_largeChartButton = nullptr;
    QChartView* m_chartView = nullptr;

    void updateChart();
    void openLargeChart();
    QChart* chartForEntry(const ResolverEntry& entry, bool large) const;
};
