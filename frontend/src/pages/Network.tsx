import EntityListPage from '../components/EntityListPage'

export default function Network() {
  return (
    <EntityListPage
      title="Network Security"
      subtitle="Firewalls, VPCs, Subnets, Security Groups, DNS, TLS, Exposure"
      apiPath="/api/v1/network"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'host', label: 'Host' },
        { key: 'port', label: 'Port' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Resource name', type: 'VPC/Subnet/SG', host: '10.0.0.1', port: '443' }}
    />
  )
}
