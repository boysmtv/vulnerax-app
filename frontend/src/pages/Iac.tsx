import EntityListPage from '../components/EntityListPage'

export default function Iac() {
  return (
    <EntityListPage
      title="Infrastructure as Code"
      subtitle="Terraform, CloudFormation, Ansible — Misconfigurations, Drift, Policy"
      apiPath="/api/v1/iac"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'filePath', label: 'File' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'IaC resource name', type: 'Terraform/CloudFormation/Ansible', filePath: 'main.tf' }}
    />
  )
}
