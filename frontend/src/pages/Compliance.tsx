import EntityListPage from '../components/EntityListPage'

export default function Compliance() {
  return (
    <EntityListPage
      title="Compliance Frameworks"
      subtitle="SOC2, ISO 27001, PCI-DSS, HIPAA, GDPR — Assessments & Evidence"
      apiPath="/api/v1/compliance/frameworks"
      columns={[
        { key: 'name', label: 'Framework' },
        { key: 'version', label: 'Version' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
    />
  )
}
