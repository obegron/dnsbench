#pragma once

#include "model/ResolverEntry.h"

#include <QList>
#include <QWidget>

class QLabel;

class ResultsTab : public QWidget {
    Q_OBJECT

public:
    explicit ResultsTab(QWidget* parent = nullptr);
    void setSummary(const QString& summary);
    void setResults(const QString& summary, const QList<ResolverEntry>& entries);

private:
    QLabel* m_label = nullptr;
};
