import EntityListPage from '../components/EntityListPage'

export default function ThreatModel() {
  return (
    <EntityListPage
      title="Threat Modeling"
      subtitle="STRIDE, PASTA — Identify threats, attack vectors, mitigations"
      apiPath="/api/v1/threat-models"
      columns={[
        { key: 'name', label: 'Model' },
        { key: 'type', label: 'Methodology' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Threat model name', type: 'STRIDE/PASTA' }}
    />
  )
}
