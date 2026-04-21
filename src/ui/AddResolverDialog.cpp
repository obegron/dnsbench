#include "ui/AddResolverDialog.h"

#include "model/ResolverModel.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHostAddress>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QUrl>
#include <QVBoxLayout>

AddResolverDialog::AddResolverDialog(QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle(QStringLiteral("Add Resolver"));

    m_nameEdit = new QLineEdit(this);
    m_addressEdit = new QLineEdit(this);
    m_protocolCombo = new QComboBox(this);
    m_portSpin = new QSpinBox(this);
    m_portSpin->setRange(1, 65535);

    m_protocolCombo->addItem(QStringLiteral("IPv4"), QVariant::fromValue(ResolverProtocol::IPv4));
    m_protocolCombo->addItem(QStringLiteral("IPv6"), QVariant::fromValue(ResolverProtocol::IPv6));
    m_protocolCombo->addItem(QStringLiteral("DoH"), QVariant::fromValue(ResolverProtocol::DoH));
    m_protocolCombo->addItem(QStringLiteral("DoT"), QVariant::fromValue(ResolverProtocol::DoT));

    auto* form = new QFormLayout;
    form->addRow(QStringLiteral("Display name"), m_nameEdit);
    form->addRow(QStringLiteral("Address / URL"), m_addressEdit);
    form->addRow(QStringLiteral("Protocol"), m_protocolCombo);
    form->addRow(QStringLiteral("Port"), m_portSpin);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, [this]() {
        if (validate()) {
            accept();
        }
    });
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(m_protocolCombo, &QComboBox::currentIndexChanged, this, &AddResolverDialog::updateDefaultPort);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(buttons);

    updateDefaultPort();
}

ResolverEntry AddResolverDialog::resolver() const
{
    ResolverEntry entry;
    entry.displayName = m_nameEdit->text().trimmed();
    entry.address = m_addressEdit->text().trimmed();
    entry.protocol = m_protocolCombo->currentData().value<ResolverProtocol>();
    entry.port = m_portSpin->value();
    entry.id = ResolverModel::makeId(entry);
    return entry;
}

void AddResolverDialog::updateDefaultPort()
{
    const ResolverProtocol protocol = m_protocolCombo->currentData().value<ResolverProtocol>();
    m_portSpin->setValue(defaultPortForProtocol(protocol));
}

bool AddResolverDialog::validate()
{
    const QString address = m_addressEdit->text().trimmed();
    const ResolverProtocol protocol = m_protocolCombo->currentData().value<ResolverProtocol>();
    if (address.isEmpty()) {
        QMessageBox::warning(this, QStringLiteral("Invalid Resolver"), QStringLiteral("Enter an address or URL."));
        return false;
    }

    if (protocol == ResolverProtocol::IPv4 || protocol == ResolverProtocol::IPv6) {
        QHostAddress host;
        if (!host.setAddress(address)) {
            QMessageBox::warning(this, QStringLiteral("Invalid Resolver"), QStringLiteral("UDP resolvers must be IP addresses."));
            return false;
        }
        if (protocol == ResolverProtocol::IPv4 && host.protocol() != QAbstractSocket::IPv4Protocol) {
            QMessageBox::warning(this, QStringLiteral("Invalid Resolver"), QStringLiteral("This resolver is not an IPv4 address."));
            return false;
        }
        if (protocol == ResolverProtocol::IPv6 && host.protocol() != QAbstractSocket::IPv6Protocol) {
            QMessageBox::warning(this, QStringLiteral("Invalid Resolver"), QStringLiteral("This resolver is not an IPv6 address."));
            return false;
        }
    } else if (protocol == ResolverProtocol::DoH) {
        const QUrl url(address.contains(QStringLiteral("://")) ? address : QStringLiteral("https://%1/dns-query").arg(address));
        if (!url.isValid() || url.host().isEmpty()) {
            QMessageBox::warning(this, QStringLiteral("Invalid Resolver"), QStringLiteral("Enter a valid DoH URL or host."));
            return false;
        }
    }

    return true;
}
