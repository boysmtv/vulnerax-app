import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

const types = ['EXECUTIVE','TECHNICAL','DEVELOPER','PENTEST','RETEST','COMPLIANCE','SUPPLY_CHAIN','POSTURE','ATTACK_SURFACE']

export default function Reports() {
  const [projectId, setProjectId] = useState('')
  const [rtype, setRtype] = useState('EXECUTIVE')
  const [format, setFormat] = useState('PDF')
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:20}})).data.data })
  const projList = projects?.content || []
  const eff = projectId || projList[0]?.id
  const { data, refetch } = useQuery({ queryKey:['reports', eff], queryFn: async()=>(await api.get('/api/v1/reports',{params:{projectId: eff}})).data.data, enabled: !!eff })

  async function generate() {
    await api.post('/api/v1/reports/generate', { projectId: eff, type: rtype, title: `${rtype} Report`, format })
    refetch()
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-end">
        <div><h1 className="text-2xl font-bold">Reporting Engine</h1><p className="text-sm text-slate-500">Executive • Technical • Developer • Pentest • Retest • Compliance (ASVS 286 controls) • Supply Chain • Posture — PDF/HTML/JSON/CSV/SARIF</p></div>
        <select value={eff} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
          {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-3">Generate Report</h3>
        <div className="flex flex-wrap gap-3">
          <select value={rtype} onChange={e=>setRtype(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
            {types.map(t=><option key={t}>{t}</option>)}
          </select>
          <select value={format} onChange={e=>setFormat(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option>PDF</option><option>HTML</option><option>JSON</option><option>CSV</option><option>SARIF</option></select>
          <button onClick={generate} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm">Generate</button>
        </div>
        <div className="text-xs text-slate-500 mt-2">White-label: custom template + logo + watermark + digital signature • Client portal for pentest provider • Classification: Public/Internal/Confidential/Restricted (MFA, expire)</div>
      </div>

      <div className="bg-white border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="text-left p-3">Report</th><th className="p-3">Type</th><th className="p-3">Format</th><th className="p-3">Classification</th><th className="p-3">Status</th><th className="p-3">Created</th><th className="p-3">Action</th></tr></thead>
          <tbody>
            {(Array.isArray(data)? data: []).map((r:any)=>(
              <tr key={r.id} className="border-t hover:bg-slate-50">
                <td className="p-3"><div className="font-medium">{r.title}</div><div className="text-xs text-slate-500">{r.id.substring(0,8)}</div></td>
                <td className="p-3"><span className="text-xs bg-slate-100 border px-2 py-1 rounded">{r.type}</span></td>
                <td className="p-3 text-xs">{r.format}</td>
                <td className="p-3 text-xs">{r.classification}</td>
                <td className="p-3"><span className="text-xs bg-emerald-100 text-emerald-700 px-2 py-1 rounded">{r.status}</span></td>
                <td className="p-3 text-xs text-slate-500">{new Date(r.createdAt).toLocaleString()}</td>
                <td className="p-3"><a href="#" onClick={async e=>{e.preventDefault(); const res=await api.get(`/api/v1/reports/${r.id}/export`,{params:{format:'JSON'}}); alert(JSON.stringify(res.data.data, null, 2).substring(0,800))}} className="text-xs text-indigo-600 hover:underline">Export</a></td>
              </tr>
            ))}
          </tbody>
        </table>
        {(!data || (Array.isArray(data)&& data.length===0)) && <div className="p-8 text-center text-sm text-slate-500">No reports. Generate executive or technical report to see AI-generated sections.</div>}
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-2">Executive Report (sample structure)</h3>
          <pre className="text-xs bg-slate-50 border p-3 rounded overflow-auto">{`Executive Summary
Overall Security Score 74/100
Risk Distribution: Critical 3, High 17
Attack Surface: 247 assets, 12 exposed
Top Security Concerns: BOLA on Payment API (Risk 94)
Trend: Critical 5→3
Remediation Progress: 39/47 Log4Shell fixed
Recommendations: patch KEV, fix authz, rotate secrets`}</pre>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-2">Compliance (ASVS 5.0)</h3>
          <pre className="text-xs bg-slate-50 border p-3 rounded overflow-auto">{`OWASP ASVS 5.0 — 286 controls
Passed 218 • Failed 34 • N/A 21 • Not Tested 13
Each control → evidence → finding trace

MASVS: storage, crypto, auth, network, platform, code, RE resilience, privacy
SSDF SP 800-218 v1.1: secure development`}</pre>
        </div>
      </div>
    </div>
  )
}
