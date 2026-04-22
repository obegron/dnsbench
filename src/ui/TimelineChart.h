#pragma once

#include "model/ResolverEntry.h"

class QChart;
class QWidget;

QChart* createTimelineChart(const ResolverEntry& entry, bool large);
void openTimelineChartDialog(QWidget* parent, const ResolverEntry& entry);
