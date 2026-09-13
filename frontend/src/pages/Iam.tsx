import EntityListPage from '../components/EntityListPage'

export default function Iam() {
  return (
    <EntityListPage
      title="IAM & Access Management"
      subtitle="Identity & Access — Users, Roles, Policies, Service Accounts, Keys"
      apiPath="/api/v1/iam"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
        { key: 'principalName', label: 'Principal' },
        { key: 'principalType', label: 'Principal Type' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Resource name', type: 'User/Role/ServiceAccount', principalName: 'principal' }}
    />
  )
}
