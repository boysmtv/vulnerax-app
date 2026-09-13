import EntityListPage from '../components/EntityListPage'

export default function Firmware() {
  return (
    <EntityListPage
      title="Firmware Security"
      subtitle="IoT / Embedded — Binary Analysis, CVE Scanning, SBOM"
      apiPath="/api/v1/firmware"
      columns={[
        { key: 'name', label: 'Name' },
        { key: 'fileName', label: 'File' },
        { key: 'status', label: 'Status' },
        { key: 'createdAt', label: 'Created', render: (v: string) => v ? new Date(v).toLocaleDateString() : '-' },
      ]}
      createFields={{ name: 'Firmware name', fileName: 'firmware.bin' }}
    />
  )
}
