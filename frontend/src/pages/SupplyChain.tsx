import EntityListPage from '../components/EntityListPage'

export default function SupplyChain() {
  return (
    <EntityListPage
      title="Supply Chain Security"
      subtitle="Provenance — Package Signing, SLSA, Dependency Verification"
      apiPath="/api/v1/provenance"
      columns={[
        { key: 'name', label: 'Package' },
        { key: 'type', label: 'Type' },
        { key: 'status', label: 'Status' },
        { key: 'verified', label: 'Verified', render: (v: boolean) => v ? <span className="text-emerald-600">Yes</span> : <span className="text-slate-400">No</span> },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Package name', type: 'NPM/MAVEN/PIP/GO' }}
    />
  )
}
