import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { Link } from 'react-router-dom'
import { useState } from 'react'

const sevColor: any = { CRITICAL:'bg-red-600 text-white', HIGH:'bg-orange-500 text-white', MEDIUM:'bg-amber-400 text-slate-900', LOW:'bg-emerald-500 text-white', INFO:'bg-slate-400 text-white' }
const riskColor: any = { CRITICAL:'text-red-600', VERY_HIGH:'text-orange-600', HIGH:'text-amber-600', MODERATE:'text-yellow-600', LOW:'text-emerald-600' }
const sevOrder: any = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 }

export default function Findings() {
  const [severity, setSeverity] = useState('')
  const [status, setStatus] = useState('')
  const [q, setQ] = useState('')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})
  const { data, refetch, isLoading } = useQuery({
    queryKey: ['findings', severity, status],
    queryFn: async () => (await api.get('/api/v1/findings', { params: { size: 200, severity: severity || undefined, status: status || undefined }})).data
  })
  const findings = data?.data?.content || []

  async function act(id: string, st: string) {
    await api.put(`/api/v1/findings/${id}/status`, { status: st, comment: 'via UI' })
    refetch()
  }

  const filtered = findings.filter((f:any)=> !q || f.title.toLowerCase().includes(q.toLowerCase()) || f.findingId.toLowerCase().includes(q.toLowerCase()) || (f.cwe||'').toLowerCase().includes(q.toLowerCase()) || (f.assetName||'').toLowerCase().includes(q.toLowerCase()))

  const grouped: Record<string, any[]> = {}
  filtered.forEach((f: any) => {
    const key = f.assetName || 'Unknown Asset'
    if (!grouped[key]) grouped[key] = []
    grouped[key].push(f)
  })

  const sortedGroups = Object.entries(grouped).sort((a, b) => {
    const aMax = Math.min(...a[1].map((f: any) => sevOrder[f.severity] ?? 5))
    const bMax = Math.min(...b[1].map((f: any) => sevOrder[f.severity] ?? 5))
    return aMax - bMax
  })

  function toggleGroup(key: string) {
    setExpanded(prev => ({ ...prev, [key]: prev[key] === false }))
  }

  function expandAll() {
    const all: Record<string, boolean> = {}
    Object.keys(grouped).forEach(k => all[k] = true)
    setExpanded(all)
  }

  function collapseAll() {
    setExpanded({})
  }

  function getGroupStats(findings: any[]) {
    const counts: Record<string, number> = {}
    findings.forEach((f: any) => { counts[f.severity] = (counts[f.severity] || 0) + 1 })
    return counts
  }

  function getGroupMaxRisk(findings: any[]) {
    const maxRisk = Math.max(...findings.map((f: any) => f.riskScore ?? 0))
    const maxLevel = findings.reduce((acc: string, f: any) => {
      if (sevOrder[f.severity] < sevOrder[acc]) return f.severity
      return acc
    }, 'INFO')
    return { maxRisk, maxLevel }
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 items-end justify-between">
        <div><h1 className="text-2xl font-bold">Vulnerability Explorer</h1><p className="text-sm text-slate-500">Grouped by Asset • {Object.keys(grouped).length} assets • {filtered.length} findings</p></div>
        <div className="flex gap-2 items-center">
          <button onClick={expandAll} className="text-xs text-indigo-600 hover:underline">Expand All</button>
          <span className="text-slate-300">|</span>
          <button onClick={collapseAll} className="text-xs text-indigo-600 hover:underline">Collapse All</button>
        </div>
      </div>

      <div className="flex gap-2">
        <input value={q} onChange={e=>setQ(e.target.value)} placeholder="Search CVE, CWE, asset..." className="border rounded-lg px-3 py-2 text-sm w-64" />
        <select value={severity} onChange={e=>setSeverity(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option value="">All severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
        <select value={status} onChange={e=>setStatus(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option value="">All status</option><option>OPEN</option><option>RESOLVED</option><option>FALSE_POSITIVE</option></select>
      </div>

      {isLoading ? <div className="text-sm text-slate-500">Loading...</div> : (
        <div className="space-y-3">
          {sortedGroups.map(([asset, assetFindings]) => {
            const stats = getGroupStats(assetFindings)
            const { maxRisk, maxLevel } = getGroupMaxRisk(assetFindings)
            const isOpen = expanded[asset] !== false
            const openCount = assetFindings.filter((f: any) => f.status === 'OPEN').length
            return (
              <div key={asset} className="bg-white rounded-xl border overflow-hidden">
                <button onClick={() => toggleGroup(asset)} className="w-full flex items-center justify-between p-4 hover:bg-slate-50 transition-colors text-left">
                  <div className="flex items-center gap-3">
                    <svg className={`w-4 h-4 text-slate-400 transition-transform ${isOpen ? 'rotate-90' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" /></svg>
                    <div>
                      <div className="font-semibold text-sm">{asset}</div>
                      <div className="text-xs text-slate-500">{assetFindings.length} findings {openCount > 0 && <span className="text-orange-600">({openCount} open)</span>}</div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    {Object.entries(stats).map(([sev, count]) => (
                      <span key={sev} className={`px-2 py-0.5 rounded text-[10px] font-semibold ${sevColor[sev] || 'bg-slate-200'}`}>{count} {sev}</span>
                    ))}
                    <span className={`text-xs font-bold ${riskColor[maxLevel] || ''}`}>Risk {maxRisk}</span>
                  </div>
                </button>

                {isOpen && (
                  <div className="border-t">
                    <table className="w-full text-sm">
                      <thead className="bg-slate-50 text-xs text-slate-500 uppercase">
                        <tr>
                          <th className="text-left p-3">Finding</th>
                          <th className="p-3">Severity</th>
                          <th className="p-3">Risk</th>
                          <th className="p-3">Source</th>
                          <th className="p-3">Status</th>
                          <th className="p-3">Owner</th>
                          <th className="p-3">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {assetFindings
                          .sort((a: any, b: any) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5))
                          .map((f: any) => (
                          <tr key={f.id} className="border-t hover:bg-slate-50">
                            <td className="p-3">
                              <Link to={`/findings/${f.id}`} className="font-medium text-indigo-600 hover:underline">{f.findingId} — {f.title}</Link>
                              <div className="text-xs text-slate-500">{f.cwe} • {f.owasp} • CVSS {f.cvss} {f.kev && <span className="bg-red-100 text-red-700 px-1.5 py-0.5 rounded text-[10px]">KEV</span>} {f.internetExposed && <span className="bg-orange-100 text-orange-700 px-1.5 py-0.5 rounded text-[10px] ml-1">Exposed</span>}</div>
                            </td>
                            <td className="p-3"><span className={`px-2 py-1 rounded text-xs font-semibold ${sevColor[f.severity]||'bg-slate-200'}`}>{f.severity}</span></td>
                            <td className={`p-3 font-semibold ${riskColor[f.riskLevel]||''}`}>{f.riskScore ?? '-'} <span className="text-xs font-normal">{f.riskLevel}</span></td>
                            <td className="p-3 text-xs text-slate-500">{f.source}</td>
                            <td className="p-3"><span className="text-xs bg-slate-100 px-2 py-1 rounded border">{f.status}</span></td>
                            <td className="p-3 text-slate-600 text-xs">{f.owner}</td>
                            <td className="p-3 flex gap-1">
                              <button onClick={()=>act(f.id,'RESOLVED')} className="text-xs border px-2 py-1 rounded hover:bg-slate-50">Resolve</button>
                              <button onClick={()=>act(f.id,'FALSE_POSITIVE')} className="text-xs border px-2 py-1 rounded hover:bg-slate-50">FP</button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            )
          })}
          {sortedGroups.length === 0 && <div className="p-8 text-center text-sm text-slate-500 bg-white rounded-xl border">No findings. Run a scan to populate.</div>}
        </div>
      )}
    </div>
  )
}
