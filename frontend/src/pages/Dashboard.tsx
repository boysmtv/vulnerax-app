import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

export default function Dashboard() {
  const { data } = useQuery({
    queryKey: ['posture'],
    queryFn: async () => (await api.get('/api/v1/dashboard/posture')).data.data
  })
  const secScore = data?.securityScore ?? (data ? 0 : 0)
  const bySev = data?.bySeverity ? Object.entries(data.bySeverity).map(([name,value])=>({name,value})) : []
  const emptyState = bySev.length===0
  const COLORS: any = { CRITICAL:'#ef4444', HIGH:'#f97316', MEDIUM:'#eab308', LOW:'#22c55e', INFO:'#64748b' }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div><h1 className="text-2xl font-bold">Security Command Center</h1><p className="text-sm text-slate-500">Organization Security Posture • Trend • Coverage • Remediation Velocity</p></div>
        <div className="flex gap-2">
          <a href="/reports" className="px-4 py-2 bg-white border rounded-lg text-sm">Generate Report</a>
          <a href="/scans" className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm">New Assessment</a>
        </div>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl border p-5">
          <div className="text-xs text-slate-500">Security Score</div>
          <div className="text-3xl font-bold mt-1">{secScore} <span className="text-sm font-normal text-slate-500">/ 100</span></div>
          <div className="mt-3 h-2 bg-slate-100 rounded-full overflow-hidden"><div className="h-full bg-indigo-600" style={{width: `${secScore}%`}} /></div>
          <div className="text-xs text-slate-400 mt-2">Transparent • App 71 • Mobile 81 • API 64 • Cloud 76</div>
        </div>
        <div className="bg-white rounded-xl border p-5"><div className="text-xs text-slate-500">Critical Risk</div><div className="text-3xl font-bold text-red-600">{data?.critical ?? 0}</div><div className="text-xs text-slate-500 mt-1">{data?.kev ?? 0} KEV • {data?.internetExposed ?? 0} exposed</div></div>
        <div className="bg-white rounded-xl border p-5"><div className="text-xs text-slate-500">High Risk</div><div className="text-3xl font-bold text-orange-500">{data?.high ?? 0}</div><div className="text-xs text-slate-500 mt-1">{data?.slaBreached ?? 0} SLA breached</div></div>
        <div className="bg-white rounded-xl border p-5"><div className="text-xs text-slate-500">Assets</div><div className="text-3xl font-bold">{data?.totalAssets ?? 0}</div><div className="text-xs text-slate-500 mt-1">{data?.internetExposed ?? 0} internet-exposed</div></div>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="bg-white rounded-xl border p-5 lg:col-span-2">
          <h3 className="font-semibold text-sm mb-4">Findings by Severity</h3>
          <div className="h-64">
            {emptyState ? <div className="h-full flex items-center justify-center text-sm text-slate-400">No findings yet — run Scan Center assessment</div> : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bySev}>
                <XAxis dataKey="name" fontSize={12} />
                <YAxis fontSize={12} />
                <Tooltip />
                <Bar dataKey="value" radius={[6,6,0,0]}>
                  {bySev.map((e,i)=><Cell key={i} fill={COLORS[e.name] || '#6366f1'} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
            )}
          </div>
        </div>
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-4">Risk Distribution</h3>
          <div className="h-64">
            {emptyState ? <div className="h-full flex items-center justify-center text-sm text-slate-400">No risk data — real risk after scans</div> : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={bySev} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}>
                  {bySev.map((e,i)=><Cell key={i} fill={COLORS[e.name] || '#6366f1'} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            )}
          </div>
          <div className="text-xs text-slate-500 mt-2">Contextual Risk = CVSS + EPSS + KEV + Criticality + Exposure + Reachability - Controls</div>
        </div>
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">Security Coverage</h3>
          <div className="space-y-2 text-sm">
            {[
              ['SAST','✓','SAST 12 langs'], ['SCA','✓','SBOM CycloneDX/SPDX'], ['Secrets','✓','Gitleaks/Trufflehog'], ['DAST','✓','ZAP browser crawl'], ['API','✓','OpenAPI/HAR'], ['Mobile','Partial','Mobsf/JADX'], ['Container','✓','Trivy/Grype'], ['Cloud','Partial','AWS/Azure/GCP'], ['Threat Model','✕','STRIDE']
            ].map(([k,v,d])=>(
              <div key={k} className="flex justify-between border-b py-2 last:border-0"><span className="text-slate-600">{k} <span className="text-xs text-slate-400">{d}</span></span><span className={v==='✓'?'text-emerald-600': v==='Partial'?'text-amber-600':'text-slate-400'}>{v}</span></div>
            ))}
          </div>
          <div className="mt-3 text-xs bg-amber-50 border border-amber-200 rounded-lg p-2 text-amber-800">Not tested ≠ No vulnerability. Coverage gap is visible to management.</div>
        </div>
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">Top Risk Applications</h3>
          <div className="space-y-3">
            {(data?.topRiskAssets && data.topRiskAssets.length>0 ? data.topRiskAssets : []).length===0 ? <div className="text-sm text-slate-400 text-center py-6">No critical assets — create project & assets</div> : (data.topRiskAssets || []).map((a:any)=>(
              <div key={a.name} className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
                <div><div className="font-medium text-sm">{a.name}</div><div className="text-xs text-slate-500">{a.type} • {a.criticality}</div></div>
                <span className="text-xs bg-red-100 text-red-700 px-2 py-1 rounded">Critical</span>
              </div>
            ))}
          </div>
          <div className="mt-4">
            <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Delta (Today vs Yesterday)</h4>
            {data?.trend ? <div className="text-sm flex gap-6"><span>Trend computed from real findings (7 days)</span></div> : <div className="text-sm text-slate-400">No history — real delta after 2 scans</div>}
          </div>
        </div>
      </div>
    </div>
  )
}
