#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QNetworkAccessManager>
#include <QUrl>

class DohResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit DohResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;

private:
    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
    QNetworkAccessManager m_network;

    QUrl endpoint() const;
};
