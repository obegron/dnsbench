#pragma once

#include <QObject>
#include <QString>

#include <functional>

class BaseResolver : public QObject {
public:
    using QueryCallback = std::function<void(qint64 rttMs, bool success)>;

    explicit BaseResolver(QObject* parent = nullptr)
        : QObject(parent)
    {
    }

    ~BaseResolver() override = default;

    virtual void query(const QString& domain, QueryCallback callback) = 0;
    virtual QString id() const = 0;
    virtual void setTimeoutMs(int timeoutMs) = 0;
    virtual QString lastErrorString() const { return {}; }
    virtual bool lastAuthenticatedDataBit() const { return false; }
    virtual void cancel() {}
};
