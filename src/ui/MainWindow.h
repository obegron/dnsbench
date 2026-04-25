#pragma once

#include "benchmark/BenchmarkController.h"
#include "model/ResolverModel.h"

#include <QHash>
#include <QMainWindow>
#include <QPoint>
#include <QSet>

class QCheckBox;
class QComboBox;
class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QSortFilterProxyModel;
class QSpinBox;
class QTableView;
class QTimer;
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
    QSpinBox* m_concurrencySpin = nullptr;
    QProgressBar* m_progress = nullptr;
    QLabel* m_etaLabel = nullptr;
    QCheckBox* m_ipv4Toggle = nullptr;
    QCheckBox* m_ipv6Toggle = nullptr;
    QCheckBox* m_dohToggle = nullptr;
    QCheckBox* m_dotToggle = nullptr;
    QCheckBox* m_verboseLogToggle = nullptr;
    QComboBox* m_resultFilterCombo = nullptr;
    ResultsTab* m_resultsTab = nullptr;
    QPlainTextEdit* m_log = nullptr;
    QTimer* m_modelFlushTimer = nullptr;
    QSet<QString> m_currentRunIds;
    QSet<QString> m_hiddenBuiltInResolverIds;
    struct PendingResolverUpdate {
        Statistics stats;
        ResolverStatus status = ResolverStatus::Finished;
        bool dnssecAuthenticatedDataSeen = false;
        QVector<ResolverSamplePoint> samples;
    };
    QHash<QString, PendingResolverUpdate> m_pendingResolverUpdates;
    QHash<QString, ResolverStatus> m_pendingStatusUpdates;

    void buildUi();
    void connectController();
    void detectSystemDns();
    void addBuiltInResolvers();
    void restoreBuiltInResolvers();
    void addResolver();
    void importResolvers();
    void startBenchmark();
    void startBenchmarkForResolver(const ResolverEntry& entry);
    void startBenchmarkForResolvers(const QList<ResolverEntry>& entries);
    void stopBenchmark();
    void exportResults();
    void cloneResults();
    void showResolverContextMenu(const QPoint& position);
    void removeSelectedResolvers();
    void openTimelineForIndex(const QModelIndex& proxyIndex);
    void queueResolverFinished(const QString& resolverId, const Statistics& stats, ResolverStatus status, bool dnssecAuthenticatedDataSeen, const QVector<ResolverSamplePoint>& samples);
    void queueResolverStatus(const QString& resolverId, ResolverStatus status);
    void flushPendingModelUpdates();
    void appendLogLine(const QString& line);
    void updateProgress(int completed, int total, qint64 elapsedMs);
    void updateConclusions();
    void loadSettings();
    void saveSettings();
    QStringList loadDomains() const;
};
