#pragma once

#include "model/ResolverEntry.h"

#include <QList>
#include <QString>

class ResultExporter {
public:
    static QString toCsv(const QList<ResolverEntry>& entries);
    static QString toTextTable(const QList<ResolverEntry>& entries);
    static bool saveCsv(const QString& path, const QList<ResolverEntry>& entries, QString* error = nullptr);
    static bool saveTextTable(const QString& path, const QList<ResolverEntry>& entries, QString* error = nullptr);
};
