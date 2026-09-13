import EntityListPage from '../components/EntityListPage'

export default function Integrations() {
  return (
    <EntityListPage
      title="Integrations"
      subtitle="SIEM, Slack, Jira, Webhooks — Connect VulneraX to your tools"
      apiPath="/api/v1/integrations"
      columns={[
        { key: 'name', label: 'Integration' },
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Integration name', type: 'SIEM/SLACK/JIRA/WEBHOOK' }}
    />
  )
}
