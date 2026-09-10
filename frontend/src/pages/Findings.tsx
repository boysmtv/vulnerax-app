import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { Link } from 'react-router-dom'
import { useState } from 'react'

const sevColor: any = { CRITICAL:'bg-red-600 text-white', HIGH:'bg-orange-500 text-white', MEDIUM:'bg-amber-400 text-slate-900', LOW:'bg-emerald-500 text-white', INFO:'bg-slate-400 text-white' }
const riskColor: any = { CRITICAL:'text-red-600', VERY_HIGH:'text-orange-600', HIGH:'text-amber-600', MODERATE:'text-yellow-600', LOW:'text-emerald-600' }

export default function Findings() {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const { data, refetch, isLoading } = useQuery({
    queryKey: ['findings', severity, status],
    queryFn: async () => (await api.get('/api/v1/findings', { params: { size: 50, severity: severity || undefined, status: status || undefined }})).data
  })
  const findings = data?.data?.content || []

  async function act(id: string, st: string) {
    await api.put(`/api/v1/findings/${id}/status`, { status: st, comment: 'via UI' })
    refetch()
  }

  const filtered = findings.filter((f:any)=> !q || f.title.toLowerCase().includes(q.toLowerCase()) || f.findingId.toLowerCase().includes(q.toLowerCase()) || (f.cwe||'').toLowerCase().includes(q.toLowerCase()))

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end justify-between">
        <div><h1 className="text-2xl font-bold">Vulnerability Explorer</h1><p className="text-sm text-slate-500">Filter by Severity • Risk • CVE • CWE • OWASP • Asset • KEV • EPSS • Exposure • Reachability</p></div>
        <div className="flex gap-2">
          <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search CVE, CWE-89, api..." className="border rounded-lg px-3 py-2 text-sm w-64" />
          <select value={severity} onChange={e=>setSeverity(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
          <select value={status} onChange={e=>setStatus(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option value="">All status</option><option>OPEN</option><option>RESOLVED</option><option>FALSE_POSITIVE</option></select>
        </div>
      </div>

      {isLoading ? <div className="text-sm text-slate-500">Loading...</div> : (
        <div className="bg-white rounded-xl border overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 text-xs text-slate-500 uppercase"><tr><th className="text-left p-3">Finding</th><th className="p-3">Severity</th><th className="p-3">Risk</th><th className="p-3">Asset</th><th className="p-3">Status</th><th className="p-3">Owner</th><th className="p-3">Actions</th></tr></thead>
              <tbody>
                {filtered.map((f:any)=>(
                  <tr key={f.id} className="border-t hover:bg-slate-50">
                    <td className="p-3">
                      <Link to={`/findings/${f.id}`} className="font-medium text-indigo-600 hover:underline">{f.findingId} — {f.title}</Link>
                      <div className="text-xs text-slate-500">{f.cwe} • {f.owasp} • CVSS {f.cvss} {f.kev && <span className="bg-red-100 text-red-700 px-1.5 py-0.5 rounded text-[10px]">KEV</span>} {f.internetExposed && <span className="bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded text-[10px] ml-1">Exposed</span>} • {f.source}</div>
                    </td>
                    <td className="p-3"><span className={`px-2 py-1 rounded text-xs font-semibold ${sevColor[f.severity]||'bg-slate-200'}`}>{f.severity}</span></td>
                    <td className={`p-3 font-semibold ${riskColor[f.riskLevel]||''}`}>{f.riskScore ?? '-'} <span className="text-xs font-normal">{f.riskLevel}</span></td>
                    <td className="p-3 text-slate-600">{f.assetName} <span className="text-xs text-slate-400">{f.environment}</span></td>
                    <td className="p-3"><span className="text-xs bg-slate-100 px-2 py-1 rounded border">{f.status}</span></td>
                    <td className="p-3 text-slate-600">{f.owner}</td>
                    <td className="p-3 flex gap-1">
                      <button onClick={()=>act(f.id,'RESOLVED')} className="text-xs border px-2 py-1 rounded hover:bg-slate-50">Resolve</button>
                      <button onClick={()=>act(f.id,'FALSE_POSITIVE')} className="text-xs border px-2 py-1 rounded hover:bg-slate-50">FP</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filtered.length===0 && <div className="p-8 text-center text-sm text-slate-500">No findings. Run a scan to populate.</div>}
        </div>
      )}
    </div>
  )
}
