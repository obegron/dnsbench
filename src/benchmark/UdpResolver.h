#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QElapsedTimer>
#include <QHostAddress>
#include <QTimer>
#include <QUdpSocket>

class UdpResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit UdpResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;
    void setTimeoutMs(int timeoutMs) override;
    QString lastErrorString() const override;
    bool lastAuthenticatedDataBit() const override;
    void cancel() override;

private:
    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
    QUdpSocket m_socket;
    QTimer m_timeout;
    QueryCallback m_callback;
    QElapsedTimer m_elapsed;
    QString m_expectedDomain;
    QString m_lastError;
    quint16 m_transactionId = 0;
    bool m_queryInFlight = false;
    bool m_lastAuthenticatedDataBit = false;

    bool ensureBound();
    void finish(qint64 rttMs, bool success);
};
