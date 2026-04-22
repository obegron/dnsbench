#include "ui/ResultsTab.h"

#include <QLabel>
#include <QVBoxLayout>

ResultsTab::ResultsTab(QWidget* parent)
    : QWidget(parent)
{
    m_label = new QLabel(QStringLiteral("No benchmark has been run yet."), this);
    m_label->setWordWrap(true);
    m_label->setTextInteractionFlags(Qt::TextSelectableByMouse);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(m_label);
    layout->addStretch();
}

void ResultsTab::setSummary(const QString& summary)
{
    setResults(summary, {});
}

void ResultsTab::setResults(const QString& summary, const QList<ResolverEntry>& entries)
{
    Q_UNUSED(entries);
    m_label->setText(summary.isEmpty() ? QStringLiteral("No benchmark has been run yet.") : summary);
}
