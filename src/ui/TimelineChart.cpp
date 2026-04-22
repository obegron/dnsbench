#include "ui/TimelineChart.h"

#include <QChart>
#include <QChartView>
#include <QDialog>
#include <QLineSeries>
#include <QLogValueAxis>
#include <QPainter>
#include <QScatterSeries>
#include <QValueAxis>
#include <QVBoxLayout>

#include <algorithm>

QChart* createTimelineChart(const ResolverEntry& entry, bool large)
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

void openTimelineChartDialog(QWidget* parent, const ResolverEntry& entry)
{
    if (entry.samples.isEmpty()) {
        return;
    }

    auto* dialog = new QDialog(parent);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("%1 Timeline").arg(entry.effectiveName()));
    dialog->resize(1100, 650);

    auto* chartView = new QChartView(createTimelineChart(entry, true), dialog);
    chartView->setRenderHint(QPainter::Antialiasing);

    auto* layout = new QVBoxLayout(dialog);
    layout->addWidget(chartView);
    dialog->show();
}
