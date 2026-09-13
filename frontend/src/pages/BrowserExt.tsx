import EntityListPage from '../components/EntityListPage'

export default function BrowserExt() {
  return (
    <EntityListPage
      title="Browser Extension Security"
      subtitle="Chrome / Firefox — Permissions, Data Leak, CSP Bypass"
      apiPath="/api/v1/browser-extensions"
      columns={[
        { key: 'name', label: 'Extension' },
        { key: 'version', label: 'Version' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Extension name', version: '1.0.0' }}
    />
  )
}
