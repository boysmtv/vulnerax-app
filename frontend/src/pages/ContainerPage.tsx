import EntityListPage from '../components/EntityListPage'

export default function ContainerPage() {
  return (
    <EntityListPage
      title="Container Security"
      subtitle="Docker, Kubernetes — Images, Registries, Runtime, Policies"
      apiPath="/api/v1/containers"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'provider', label: 'Provider' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Container name', type: 'Docker/K8s', provider: 'EKS/GKE/AKS' }}
    />
  )
}
