import EntityListPage from '../components/EntityListPage'

export default function DatabasePage() {
  return (
    <EntityListPage
      title="Database Security"
      subtitle="PostgreSQL, MySQL, MongoDB, Redis — Access, Encryption, Exposure"
      apiPath="/api/v1/databases"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'host', label: 'Host' },
        { key: 'port', label: 'Port' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Database name', type: 'PostgreSQL/MySQL/MongoDB', host: 'db.example.com', port: '5432' }}
    />
  )
}
