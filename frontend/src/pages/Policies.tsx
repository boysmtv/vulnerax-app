import EntityListPage from '../components/EntityListPage'

export default function Policies() {
  return (
    <EntityListPage
      title="Security Policies"
      subtitle="Rules, Gates, Exceptions — Enforce security standards across projects"
      apiPath="/api/v1/policies"
      columns={[
        { key: 'name', label: 'Policy' },
        { key: 'type', label: 'Type' },
        { key: 'severity', label: 'Severity' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Policy name', type: 'GATE/ALERT/BLOCK', severity: 'CRITICAL/HIGH/MEDIUM' }}
    />
  )
}
