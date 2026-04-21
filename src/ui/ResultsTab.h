#pragma once

#include <QWidget>

class QLabel;

class ResultsTab : public QWidget {
    Q_OBJECT

public:
    explicit ResultsTab(QWidget* parent = nullptr);
    void setSummary(const QString& summary);

private:
    QLabel* m_label = nullptr;
};
