import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Assets() {
  const [projectId, setProjectId] = useState('')
  const [type, setType] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [form, setForm] = useState({ name:'', type:'API', identifier:'', technology:'', criticality:'MEDIUM', internetExposed:false })
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:50}})).data.data })
  const projList = projects?.content || []
  const effectiveProj = projectId || projList[0]?.id
  const { data, refetch } = useQuery({
    queryKey:['assets', effectiveProj, type],
    queryFn: async()=>(await api.get('/api/v1/assets',{params:{ projectId: effectiveProj, type: type||undefined, size:50 }})).data.data,
    enabled: !!effectiveProj
  })
  const stats = useQuery({ queryKey:['asset-stats', effectiveProj], queryFn: async()=>(await api.get('/api/v1/assets/stats',{params:{projectId:effectiveProj}})).data.data, enabled: !!effectiveProj })

  async function create() {
    if (!effectiveProj) return alert('Create project first')
    const orgId = projList.find((p:any)=>p.id===effectiveProj)?.organizationId
    await api.post('/api/v1/assets',{ projectId: effectiveProj, organizationId: orgId, name: form.name, type: form.type, identifier: form.identifier, technology: form.technology, criticality: form.criticality, internetExposed: form.internetExposed })
    setShowNew(false); setForm({ name:'', type:'API', identifier:'', technology:'', criticality:'MEDIUM', internetExposed:false }); refetch()
  }
  async function discover() {
    await api.post('/api/v1/assets/discover', null, { params:{ projectId: effectiveProj, source:'MANUAL' } })
    refetch()
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap justify-between gap-3 items-end">
        <div><h1 className="text-2xl font-bold">Asset Inventory</h1><p className="text-sm text-slate-500">Domain • IP • API • Repo • Mobile • Container • K8s • Cloud • DB • Bucket — Single inventory with delta</p></div>
        <div className="flex gap-2">
          <select value={effectiveProj} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
            {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <select value={type} onChange={e=>setType(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option value="">All types</option><option>API</option><option>DOMAIN</option><option>REPOSITORY</option><option>MOBILE_APP</option><option>CONTAINER_IMAGE</option><option>DATABASE</option></select>
          <button onClick={discover} className="px-4 py-2 border rounded-lg text-sm bg-white">Discover</button>
          <button onClick={()=>setShowNew(!showNew)} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm">New Asset</button>
        </div>
      </div>

      {stats.data && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="bg-white border rounded-xl p-4"><div className="text-xs text-slate-500">Total Assets</div><div className="text-2xl font-bold">{stats.data.total}</div></div>
          <div className="bg-white border rounded-xl p-4"><div className="text-xs text-slate-500">Internet Exposed</div><div className="text-2xl font-bold text-orange-600">{stats.data.internetExposed}</div></div>
          <div className="bg-white border rounded-xl p-4"><div className="text-xs text-slate-500">New (24h)</div><div className="text-2xl font-bold text-emerald-600">{stats.data.discoveryDelta?.newLast24h ?? 0}</div></div>
          <div className="bg-white border rounded-xl p-4"><div className="text-xs text-slate-500">Shadow / Unknown</div><div className="text-2xl font-bold">{(Object.values(stats.data.byType as any || {}) as any[]).reduce((a:any,b:any)=> (a as number)+(b as number),0) as number - (stats.data.total as number) + ((stats.data.byType as any)?.SHADOW||0)}</div></div>
        </div>
      )}

      {showNew && (
        <div className="bg-white border rounded-xl p-5 space-y-3">
          <h3 className="font-semibold">Register Asset</h3>
          <div className="grid md:grid-cols-3 gap-3">
            <input placeholder="Name (e.g. Payment API)" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} className="border rounded-lg px-3 py-2 text-sm" />
            <select value={form.type} onChange={e=>setForm({...form,type:e.target.value})} className="border rounded-lg px-3 py-2 text-sm">
              <option>API</option><option>DOMAIN</option><option>SUBDOMAIN</option><option>REPOSITORY</option><option>MOBILE_APP</option><option>CONTAINER_IMAGE</option><option>K8S_CLUSTER</option><option>DATABASE</option><option>BUCKET</option><option>IP</option><option>URL</option>
            </select>
            <input placeholder="Identifier (domain, image, repo url)" value={form.identifier} onChange={e=>setForm({...form,identifier:e.target.value})} className="border rounded-lg px-3 py-2 text-sm" />
            <input placeholder="Technology" value={form.technology} onChange={e=>setForm({...form,technology:e.target.value})} className="border rounded-lg px-3 py-2 text-sm" />
            <select value={form.criticality} onChange={e=>setForm({...form,criticality:e.target.value})} className="border rounded-lg px-3 py-2 text-sm"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
            <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.internetExposed} onChange={e=>setForm({...form,internetExposed:e.target.checked})} /> Internet Exposed</label>
          </div>
          <button onClick={create} className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm">Create</button>
        </div>
      )}

      <div className="bg-white border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-50 text-xs uppercase text-slate-500"><tr><th className="text-left p-3">Asset</th><th className="p-3">Type</th><th className="p-3">Env</th><th className="p-3">Criticality</th><th className="p-3">Exposure</th><th className="p-3">Owner</th></tr></thead>
          <tbody>
            {(data?.content||[]).map((a:any)=>(
              <tr key={a.id} className="border-t hover:bg-slate-50">
                <td className="p-3"><div className="font-medium">{a.name}</div><div className="text-xs text-slate-500">{a.identifier} • {a.technology}</div></td>
                <td className="p-3"><span className="text-xs bg-slate-100 border px-2 py-1 rounded">{a.type}</span></td>
                <td className="p-3 text-xs">{a.environment}</td>
                <td className="p-3"><span className={`text-xs px-2 py-1 rounded ${a.criticality==='CRITICAL'?'bg-red-100 text-red-700': a.criticality==='HIGH'?'bg-orange-100 text-orange-700':'bg-slate-100'}`}>{a.criticality}</span></td>
                <td className="p-3">{a.internetExposed ? <span className="text-xs bg-orange-100 text-orange-700 px-2 py-1 rounded">Exposed</span> : <span className="text-xs text-slate-400">Internal</span>}</td>
                <td className="p-3 text-slate-600">{a.owner || a.team || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {(data?.content||[]).length===0 && <div className="p-8 text-center text-sm text-slate-500">No assets for this project. Create or Discover.</div>}
      </div>
    </div>
  )
}
