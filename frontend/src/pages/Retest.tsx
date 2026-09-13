import EntityListPage from '../components/EntityListPage'

export default function Retest() {
  return (
    <EntityListPage
      title="Retest & Verification"
      subtitle="Verify remediation — Retest findings, track closure"
      apiPath="/api/v1/retests"
      columns={[
        { key: 'findingId', label: 'Finding' },
        { key: 'status', label: 'Status' },
        { key: 'result', label: 'Result' },
        { key: 'comment', label: 'Comment' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ findingId: 'FND-XXXX', comment: 'Retest reason' }}
    />
  )
}
