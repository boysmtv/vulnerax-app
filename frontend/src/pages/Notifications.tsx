import EntityListPage from '../components/EntityListPage'

export default function Notifications() {
  return (
    <EntityListPage
      title="Notifications"
      subtitle="Alerts — Severity, SLA Breach, Scan Complete, Policy Violation"
      apiPath="/api/v1/notifications"
      columns={[
        { key: 'title', label: 'Title' },
        { key: 'type', label: 'Type' },
        { key: 'severity', label: 'Severity' },
        { key: 'read', label: 'Read', render: (v: boolean) => v ? <span className="text-emerald-600">Read</span> : <span className="text-blue-600 font-medium">Unread</span> },
        { key: 'createdAt', label: 'Time', render: (v: string) => v ? new Date(v).toLocaleString() : '-' },
      ]}
    />
  )
}
