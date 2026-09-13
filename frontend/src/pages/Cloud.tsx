import EntityListPage from '../components/EntityListPage'

export default function Cloud() {
  return (
    <EntityListPage
      title="Cloud Security"
      subtitle="AWS / Azure / GCP — IAM, Network, Storage, Compute, Logging, Exposure"
      apiPath="/api/v1/cloud"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'provider', label: 'Provider' },
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
        { key: 'region', label: 'Region' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Resource name', provider: 'AWS/Azure/GCP', type: 'IAM/VM/S3/RDS' }}
    />
  )
}
