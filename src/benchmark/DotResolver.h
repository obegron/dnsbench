#pragma once

#include "benchmark/BaseResolver.h"
#include "model/ResolverEntry.h"

#include <QSslSocket>
#include <QTimer>

class DotResolver : public BaseResolver {
    Q_OBJECT

public:
    explicit DotResolver(const ResolverEntry& entry, int timeoutMs = 5000, QObject* parent = nullptr);

    void query(const QString& domain, QueryCallback callback) override;
    QString id() const override;
    void cancel() override;

private:
    ResolverEntry m_entry;
    int m_timeoutMs = 5000;
    QSslSocket m_socket;
    QByteArray m_buffer;
    QTimer m_timeout;
    QueryCallback m_callback;
    qint64 m_startedAt = 0;
    quint16 m_transactionId = 0;
    bool m_queryInFlight = false;

    void sendCurrentQuery(const QByteArray& dnsPacket);
    void finish(qint64 rttMs, bool success);
};
