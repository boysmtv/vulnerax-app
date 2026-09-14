import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

interface Column {
  key: string
  label: string
  render?: (val: any, row: any) => React.ReactNode
  className?: string
}

interface CreateField {
  key: string
  label: string
  type?: string
  required?: boolean
}

interface EntityListPageProps {
  title: string
  subtitle: string
  apiPath: string
  columns: Column[]
  createFields?: CreateField[] | Record<string, string>
  nameLabel?: string
}

const statusColor: Record<string, string> = {
  ACTIVE: 'bg-emerald-100 text-emerald-700',
  ENABLED: 'bg-emerald-100 text-emerald-700',
  OPEN: 'bg-blue-100 text-blue-700',
  PENDING: 'bg-amber-100 text-amber-700',
  DISABLED: 'bg-slate-200 text-slate-600',
  CLOSED: 'bg-slate-200 text-slate-600',
  FAILED: 'bg-red-100 text-red-700',
  ERROR: 'bg-red-100 text-red-700',
}

export default function EntityListPage({ title, subtitle, apiPath, columns, createFields, nameLabel = 'name' }: EntityListPageProps) {
  const [projectId, setProjectId] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState<Record<string, string>>({})

  const { data: projects } = useQuery({
    queryKey: ['projects'],
    queryFn: async () => (await api.get('/api/v1/projects', { params: { size: 20 } })).data.data
  })
  const projList = (projects as any)?.content || []
  const eff = projectId || (projList[0] as any)?.id

  const { data, refetch, isLoading } = useQuery({
    queryKey: [apiPath, eff],
    queryFn: async () => (await api.get(apiPath, { params: { projectId: eff, organizationId: eff, size: 50 } })).data.data,
    enabled: !!eff
  })
  const list = Array.isArray(data) ? data : (data as any)?.content || []

  async function handleCreate() {
    try {
      const payload = { projectId: eff, organizationId: eff, ...form }
      await api.post(apiPath, payload)
      refetch()
      setShowCreate(false)
      setForm({})
    } catch (e: any) {
      alert(e.response?.data?.message || e.message)
    }
  }

  function cellValue(row: any, col: Column) {
    const val = row[col.key]
    if (col.render) return col.render(val, row)
    if (val == null || val === '') return <span className="text-slate-400">-</span>
    if (typeof val === 'boolean') return val ? <span className="text-emerald-600">Yes</span> : <span className="text-slate-400">No</span>
    const str = String(val)
    const lower = str.toUpperCase()
    if (['ACTIVE', 'ENABLED', 'OPEN', 'PENDING', 'DISABLED', 'CLOSED', 'FAILED', 'ERROR', 'READY', 'RUNNING', 'QUEUED', 'COMPLETED'].includes(lower)) {
      return <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColor[lower] || 'bg-slate-100 text-slate-600'}`}>{str}</span>
    }
    if (str.length > 60) return <span title={str}>{str.substring(0, 60)}...</span>
    return str
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end justify-between">
        <div>
          <h1 className="text-2xl font-bold">{title}</h1>
          <p className="text-sm text-slate-500">{subtitle}</p>
        </div>
        <div className="flex gap-2 items-center">
          <select value={eff || ''} onChange={e => setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
            {projList.map((p: any) => <option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          {createFields && (
            <button onClick={() => setShowCreate(!showCreate)} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-indigo-700">
              {showCreate ? 'Cancel' : `+ New`}
            </button>
          )}
        </div>
      </div>

      {showCreate && createFields && (
        <div className="bg-white border rounded-xl p-4 space-y-3">
          <h3 className="font-semibold text-sm">Create New {title.replace(/s$/, '')}</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {Array.isArray(createFields)
              ? createFields.map((field) => (
                  <input
                    key={field.key}
                    value={form[field.key] || ''}
                    onChange={e => setForm({ ...form, [field.key]: e.target.value })}
                    placeholder={field.label}
                    className="border rounded-lg px-3 py-2 text-sm"
                  />
                ))
              : Object.entries(createFields).map(([key, placeholder]) => (
                  <input
                    key={key}
                    value={form[key] || ''}
                    onChange={e => setForm({ ...form, [key]: e.target.value })}
                    placeholder={placeholder}
                    className="border rounded-lg px-3 py-2 text-sm"
                  />
                ))
            }
          </div>
          <button onClick={handleCreate} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm hover:bg-indigo-700">Create</button>
        </div>
      )}

      {isLoading ? (
        <div className="text-sm text-slate-500 py-8 text-center">Loading...</div>
      ) : (
        <div className="bg-white rounded-xl border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
                <tr>
                  {columns.map(col => (
                    <th key={col.key} className={`text-left p-3 ${col.className || ''}`}>{col.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {list.length === 0 ? (
                  <tr><td colSpan={columns.length} className="p-8 text-center text-sm text-slate-400">No data yet</td></tr>
                ) : (
                  list.map((row: any, i: number) => (
                    <tr key={row.id || i} className="border-t hover:bg-slate-50">
                      {columns.map(col => (
                        <td key={col.key} className={`p-3 ${col.className || ''}`}>
                          {cellValue(row, col)}
                        </td>
                      ))}
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <div className="p-2 text-xs text-slate-400 border-t bg-slate-50 text-right">{list.length} records</div>
        </div>
      )}
    </div>
  )
}
