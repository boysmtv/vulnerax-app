import EntityListPage from '../components/EntityListPage'

export default function Campaigns() {
  return (
    <EntityListPage
      title="Security Campaigns"
      subtitle="Bug Bounty, Security Assessments — Scope, Submissions, Rewards"
      apiPath="/api/v1/campaigns"
      columns={[
        { key: 'name', label: 'Campaign' },
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Campaign name', type: 'BUG_BOUNTY/ASSESSMENT' }}
    />
  )
}
