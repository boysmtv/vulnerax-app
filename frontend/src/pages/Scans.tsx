import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Scans() {
  const [projectId, setProjectId] = useState('')
  const [form, setForm] = useState({ scannerType:'SAST', profile:'STANDARD', target:'' })
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:50}})).data.data })
  const projList = projects?.content || []
  const eff = projectId || projList[0]?.id
  const { data, refetch } = useQuery({ queryKey:['scans', eff], queryFn: async()=>(await api.get('/api/v1/scans',{params:{projectId: eff, size:20}})).data.data, enabled: !!eff })

  const s = useQuery({ queryKey:['scan-stats'], queryFn: async()=>(await api.get('/api/v1/dashboard/posture')).data.data })

  async function start() {
    if (!eff) return alert('Create project first')
    await api.post('/api/v1/scans', { projectId: eff, scannerType: form.scannerType, profile: form.profile, target: form.target || 'auto' })
    setTimeout(()=>refetch(), 1500)
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-end">
        <div><h1 className="text-2xl font-bold">Scan Center</h1><p className="text-sm text-slate-500">Queued • Running • Completed • Failed — Kafka orchestrator + isolated workers</p></div>
        <select value={eff} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
          {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-3">New Assessment Wizard (1. Select Project 2. Select Asset 3. Verify Authorization 4. Profile 5. Auth 6. Schedule 7. Review 8. Run)</h3>
        <div className="grid md:grid-cols-4 gap-3">
          <select value={form.scannerType} onChange={e=>setForm({...form, scannerType:e.target.value})} className="border rounded-lg px-3 py-2 text-sm">
            <option>SAST</option><option>SCA</option><option>SECRET</option><option>DAST</option><option>API</option><option>MOBILE</option><option>CONTAINER</option><option>IAC</option><option>CLOUD</option>
          </select>
          <select value={form.profile} onChange={e=>setForm({...form, profile:e.target.value})} className="border rounded-lg px-3 py-2 text-sm">
            <option>PASSIVE</option><option>QUICK</option><option>STANDARD</option><option>DEEP</option><option>RELEASE_GATE</option><option>CONTINUOUS</option>
          </select>
          <input placeholder="Target (repo url, image, domain, apk)" value={form.target} onChange={e=>setForm({...form,target:e.target.value})} className="border rounded-lg px-3 py-2 text-sm" />
          <button onClick={start} className="bg-indigo-600 text-white rounded-lg px-4 py-2 text-sm font-medium">Run Assessment</button>
        </div>
        <div className="text-xs text-slate-500 mt-2">Scope requires Allowed targets + Excluded paths + Approval + Ownership verification (DNS TXT / File / Cloud). Workers have network policy + CPU/mem limit + sandbox.</div>
      </div>

      <div className="bg-white border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="text-left p-3">Scan</th><th className="p-3">Profile</th><th className="p-3">Status</th><th className="p-3">Findings</th><th className="p-3">Duration</th><th className="p-3">Initiated</th></tr></thead>
          <tbody>
            {(data?.content||[]).map((sc:any)=>(
              <tr key={sc.id} className="border-t hover:bg-slate-50">
                <td className="p-3"><div className="font-medium">{sc.scannerType} • {sc.target}</div><div className="text-xs text-slate-500">{sc.id.substring(0,8)} • {new Date(sc.createdAt).toLocaleString()}</div></td>
                <td className="p-3 text-xs"><span className="bg-slate-100 border px-2 py-1 rounded">{sc.profile}</span></td>
                <td className="p-3"><span className={`text-xs px-2 py-1 rounded ${sc.status==='COMPLETED'?'bg-emerald-100 text-emerald-700': sc.status==='RUNNING'?'bg-blue-100 text-blue-700 animate-pulse': sc.status==='QUEUED'?'bg-amber-100 text-amber-700':'bg-red-100 text-red-700'}`}>{sc.status}</span></td>
                <td className="p-3">{sc.findingsCount ?? '-'}</td>
                <td className="p-3 text-xs">{sc.durationMs ? `${(sc.durationMs/1000).toFixed(1)}s` : '-'}</td>
                <td className="p-3 text-xs text-slate-500">{sc.initiatedBy}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(data?.content||[]).length===0 && <div className="p-8 text-center text-sm text-slate-500">No scans yet. Run first assessment to see Findings → Risk → AI → Report flow.</div>}
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-2">Scan Orchestrator</h3>
        <pre className="text-xs bg-slate-900 text-slate-100 p-4 rounded-lg overflow-auto">{`               Scan Orchestrator
                      │
                    Kafka
                      │
  ┌──────────────┬────┼───────┬─────────────┐
  ▼              ▼    ▼       ▼             ▼
 SAST          SCA  DAST   Mobile        Cloud
 Worker      Worker Worker Worker        Worker
  │             │     │       │             │
  └─────────────┼─────┼───────┼─────────────┘
                ▼     ▼       ▼
         Finding Normalizer → Deduplication → Correlation → Risk → AI`}
        </pre>
      </div>
    </div>
  )
}
