#include "ui/TimelineChart.h"

#include <QChart>
#include <QChartView>
#include <QCheckBox>
#include <QDialog>
#include <QHBoxLayout>
#include <QLineSeries>
#include <QLogValueAxis>
#include <QPainter>
#include <QScatterSeries>
#include <QValueAxis>
#include <QVBoxLayout>

#include <algorithm>

namespace {

QChart* createTimelineChart(const ResolverEntry& entry, bool large, bool overlayPasses)
{
    auto* chart = new QChart();
    chart->legend()->setVisible(true);
    chart->setTitle(overlayPasses
            ? QStringLiteral("%1 response timeline (passes overlaid)").arg(entry.effectiveName())
            : QStringLiteral("%1 response timeline").arg(entry.effectiveName()));

    const QVector<QVector<ResolverSamplePoint>> passes = entry.passSamples.isEmpty()
        ? QVector<QVector<ResolverSamplePoint>>{entry.samples}
        : entry.passSamples;

    QList<QLineSeries*> rttSeries;
    auto* lossSeries = new QScatterSeries(chart);
    lossSeries->setName(QStringLiteral("Loss"));
    lossSeries->setMarkerShape(QScatterSeries::MarkerShapeRectangle);
    lossSeries->setMarkerSize(large ? 9.0 : 7.0);
    lossSeries->setColor(QColor(205, 67, 54));
    lossSeries->setBorderColor(QColor(205, 67, 54));

    const QVector<QColor> colors = {
        QColor(57, 154, 89),
        QColor(66, 135, 245),
        QColor(210, 154, 45),
        QColor(147, 96, 216),
        QColor(36, 169, 181),
    };

    qreal maxRtt = 1.0;
    int maxSample = 1;
    int sampleOffset = 0;
    for (int pass = 0; pass < passes.size(); ++pass) {
        auto* series = new QLineSeries(chart);
        series->setName(passes.size() > 1
                ? QStringLiteral("Pass %1").arg(pass + 1)
                : QStringLiteral("RTT (ms, log scale)"));
        series->setColor(colors.at(pass % colors.size()));

        const QVector<ResolverSamplePoint>& samples = passes.at(pass);
        for (const ResolverSamplePoint& sample : samples) {
            const int sampleIndex = (overlayPasses ? 0 : sampleOffset) + sample.sampleIndex + 1;
            const qreal x = sampleIndex;
            maxSample = std::max(maxSample, sampleIndex);
            if (sample.success) {
                const qreal y = std::max<qint64>(1, sample.rttMs);
                series->append(x, y);
                maxRtt = std::max(maxRtt, y);
            } else {
                lossSeries->append(x, 1.0);
            }
        }
        if (!overlayPasses) {
            sampleOffset += samples.size();
        }
        rttSeries.push_back(series);
    }

    for (QLineSeries* series : rttSeries) {
        chart->addSeries(series);
    }
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
    for (QLineSeries* series : rttSeries) {
        series->attachAxis(axisX);
        series->attachAxis(axisY);
    }
    lossSeries->attachAxis(axisX);
    lossSeries->attachAxis(axisY);

    return chart;
}

}

QChart* createTimelineChart(const ResolverEntry& entry, bool large)
{
    return createTimelineChart(entry, large, false);
}

void openTimelineChartDialog(QWidget* parent, const ResolverEntry& entry)
{
    if (entry.samples.isEmpty() && entry.passSamples.isEmpty()) {
        return;
    }

    auto* dialog = new QDialog(parent);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setWindowTitle(QStringLiteral("%1 Timeline").arg(entry.effectiveName()));
    dialog->resize(1100, 650);

    auto* chartView = new QChartView(createTimelineChart(entry, true, false), dialog);
    chartView->setRenderHint(QPainter::Antialiasing);

    auto* overlayToggle = new QCheckBox(QStringLiteral("Overlay passes"), dialog);
    overlayToggle->setEnabled(entry.passSamples.size() > 1);
    overlayToggle->setToolTip(QStringLiteral("Draw each pass against the same sample numbers instead of end-to-end."));
    QObject::connect(overlayToggle, &QCheckBox::toggled, chartView, [chartView, entry](bool checked) {
        chartView->setChart(createTimelineChart(entry, true, checked));
    });

    auto* controls = new QHBoxLayout();
    controls->addWidget(overlayToggle);
    controls->addStretch();

    auto* layout = new QVBoxLayout(dialog);
    layout->addLayout(controls);
    layout->addWidget(chartView);
    dialog->show();
}
