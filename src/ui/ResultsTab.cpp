#include "ui/ResultsTab.h"

#include <QChart>
#include <QChartView>
#include <QComboBox>
#include <QDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineSeries>
#include <QLogValueAxis>
#include <QPainter>
#include <QPushButton>
#include <QScatterSeries>
#include <QValueAxis>
#include <QVBoxLayout>

#include <algorithm>

ResultsTab::ResultsTab(QWidget* parent)
    : QWidget(parent)
{
    m_label = new QLabel(QStringLiteral("No benchmark has been run yet."), this);
    m_label->setWordWrap(true);
    m_label->setTextInteractionFlags(Qt::TextSelectableByMouse);

    m_resolverPicker = new QComboBox(this);
    m_largeChartButton = new QPushButton(QStringLiteral("Open Large Chart"), this);
    m_chartView = new QChartView(new QChart(), this);
    m_chartView->setRenderHint(QPainter::Antialiasing);
    m_chartView->setMinimumHeight(240);

    connect(m_resolverPicker, &QComboBox::currentIndexChanged, this, &ResultsTab::updateChart);
    connect(m_largeChartButton, &QPushButton::clicked, this, &ResultsTab::openLargeChart);

    auto* controls = new QHBoxLayout();
    controls->addWidget(m_resolverPicker, 1);
    controls->addWidget(m_largeChartButton);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(m_label);
    layout->addLayout(controls);
    layout->addWidget(m_chartView, 1);

    m_resolverPicker->hide();
    m_largeChartButton->hide();
    m_chartView->hide();
}

void ResultsTab::setSummary(const QString& summary)
{
    setResults(summary, {});
}

void ResultsTab::setResults(const QString& summary, const QList<ResolverEntry>& entries)
{
    m_label->setText(summary.isEmpty() ? QStringLiteral("No benchmark has been run yet.") : summary);

    m_entries.clear();
    for (const ResolverEntry& entry : entries) {
        if (entry.status == ResolverStatus::Finished && !entry.samples.isEmpty()) {
            m_entries.push_back(entry);
        }
    }

    std::sort(m_entries.begin(), m_entries.end(), [](const ResolverEntry& left, const ResolverEntry& right) {
        if (left.stats.lossPercent != right.stats.lossPercent) {
            return left.stats.lossPercent < right.stats.lossPercent;
        }
        if (left.stats.medianMs != right.stats.medianMs) {
            return left.stats.medianMs < right.stats.medianMs;
        }
        return left.stats.p90Ms < right.stats.p90Ms;
    });

    m_resolverPicker->blockSignals(true);
    m_resolverPicker->clear();
    for (int i = 0; i < m_entries.size(); ++i) {
        m_resolverPicker->addItem(m_entries.at(i).effectiveName(), i);
    }
    m_resolverPicker->blockSignals(false);

    const bool hasChartData = !m_entries.isEmpty();
    m_resolverPicker->setVisible(hasChartData);
    m_largeChartButton->setVisible(hasChartData);
    m_chartView->setVisible(hasChartData);
    updateChart();
}

void ResultsTab::updateChart()
{
    if (m_entries.isEmpty()) {
        m_chartView->setChart(new QChart());
        return;
    }

    const int index = std::clamp(m_resolverPicker->currentIndex(), 0, static_cast<int>(m_entries.size()) - 1);
    m_chartView->setChart(chartForEntry(m_entries.at(index), false));
}

void ResultsTab::openLargeChart()
{
    if (m_entries.isEmpty()) {
        return;
    }

    const int index = std::clamp(m_resolverPicker->currentIndex(), 0, static_cast<int>(m_entries.size()) - 1);
    auto* dialog = new QDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("%1 Timeline").arg(m_entries.at(index).effectiveName()));
    dialog->resize(1100, 650);

    auto* chartView = new QChartView(chartForEntry(m_entries.at(index), true), dialog);
    chartView->setRenderHint(QPainter::Antialiasing);

    auto* layout = new QVBoxLayout(dialog);
    layout->addWidget(chartView);
    dialog->show();
}

QChart* ResultsTab::chartForEntry(const ResolverEntry& entry, bool large) const
{
    auto* chart = new QChart();
    chart->legend()->setVisible(true);
    chart->setTitle(QStringLiteral("%1 response timeline").arg(entry.effectiveName()));

    auto* rttSeries = new QLineSeries(chart);
    rttSeries->setName(QStringLiteral("RTT (ms, log scale)"));
    auto* lossSeries = new QScatterSeries(chart);
    lossSeries->setName(QStringLiteral("Loss"));
    lossSeries->setMarkerShape(QScatterSeries::MarkerShapeRectangle);
    lossSeries->setMarkerSize(large ? 9.0 : 7.0);
    lossSeries->setColor(QColor(205, 67, 54));
    lossSeries->setBorderColor(QColor(205, 67, 54));

    qreal maxRtt = 1.0;
    int maxSample = 1;
    for (const ResolverSamplePoint& sample : entry.samples) {
        const qreal x = sample.sampleIndex + 1;
        maxSample = std::max(maxSample, sample.sampleIndex + 1);
        if (sample.success) {
            const qreal y = std::max<qint64>(1, sample.rttMs);
            rttSeries->append(x, y);
            maxRtt = std::max(maxRtt, y);
        } else {
            lossSeries->append(x, 1.0);
        }
    }

    chart->addSeries(rttSeries);
    chart->addSeries(lossSeries);

    auto* axisX = new QValueAxis(chart);
    axisX->setTitleText(QStringLiteral("Sample"));
    axisX->setRange(1, std::max(2, maxSample));
    axisX->setLabelFormat("%d");
    axisX->setTickCount(large ? 12 : 6);

    auto* axisY = new QLogValueAxis(chart);
    axisY->setTitleText(QStringLiteral("Response time"));
    axisY->setBase(10);
    axisY->setLabelFormat("%g ms");
    axisY->setRange(1.0, std::max(10.0, maxRtt * 1.25));

    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);
    rttSeries->attachAxis(axisX);
    rttSeries->attachAxis(axisY);
    lossSeries->attachAxis(axisX);
    lossSeries->attachAxis(axisY);

    return chart;
}
