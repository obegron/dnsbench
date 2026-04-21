#pragma once

#include "model/ResolverEntry.h"

#include <QDialog>

class QComboBox;
class QLineEdit;
class QSpinBox;

class AddResolverDialog : public QDialog {
    Q_OBJECT

public:
    explicit AddResolverDialog(QWidget* parent = nullptr);

    ResolverEntry resolver() const;

private:
    QLineEdit* m_nameEdit = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QComboBox* m_protocolCombo = nullptr;
    QSpinBox* m_portSpin = nullptr;

    void updateDefaultPort();
    bool validate();
};
