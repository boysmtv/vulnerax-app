import EntityListPage from '../components/EntityListPage'

export default function K8s() {
  return (
    <EntityListPage
      title="Kubernetes Security"
      subtitle="Cluster • RBAC • Privilege • NetworkPolicy • Pod Security"
      apiPath="/api/v1/k8s"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'clusterName', label: 'Cluster' },
        { key: 'namespace', label: 'Namespace' },
        { key: 'kind', label: 'Kind' },
        { key: 'status', label: 'Status' },
      ]}
      createFields={[
        { key: 'name', label: 'Resource Name', type: 'text', required: true },
        { key: 'clusterName', label: 'Cluster', type: 'text', required: true },
        { key: 'kind', label: 'Kind (Pod/Service/Deployment)', type: 'text', required: true },
        { key: 'namespace', label: 'Namespace', type: 'text' },
        { key: 'projectId', label: 'Project ID', type: 'text', required: true },
      ]}
    />
  )
}
