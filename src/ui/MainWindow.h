#pragma once

#include "benchmark/BenchmarkController.h"
#include "model/ResolverModel.h"

#include <QMainWindow>
#include <QPoint>
#include <QSet>

class QCheckBox;
class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QSortFilterProxyModel;
class QSpinBox;
class QTableView;
class ResultsTab;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

private:
    ResolverModel m_model;
    QSortFilterProxyModel* m_proxy = nullptr;
    BenchmarkController m_controller;
    QTableView* m_table = nullptr;
    QSpinBox* m_sampleSpin = nullptr;
    QSpinBox* m_delaySpin = nullptr;
    QProgressBar* m_progress = nullptr;
    QLabel* m_etaLabel = nullptr;
    QCheckBox* m_ipv4Toggle = nullptr;
    QCheckBox* m_ipv6Toggle = nullptr;
    QCheckBox* m_dohToggle = nullptr;
    QCheckBox* m_dotToggle = nullptr;
    QCheckBox* m_verboseLogToggle = nullptr;
    ResultsTab* m_resultsTab = nullptr;
    QPlainTextEdit* m_log = nullptr;
    QSet<QString> m_currentRunIds;
    QSet<QString> m_hiddenBuiltInResolverIds;

    void buildUi();
    void connectController();
    void detectSystemDns();
    void addBuiltInResolvers();
    void restoreBuiltInResolvers();
    void addResolver();
    void importResolvers();
    void startBenchmark();
    void startBenchmarkForResolver(const ResolverEntry& entry);
    void stopBenchmark();
    void exportResults();
    void cloneResults();
    void showResolverContextMenu(const QPoint& position);
    void openTimelineForIndex(const QModelIndex& proxyIndex);
    void appendLogLine(const QString& line);
    void updateProgress(int completed, int total, qint64 elapsedMs);
    void updateConclusions();
    void loadSettings();
    void saveSettings();
    QStringList loadDomains() const;
};
