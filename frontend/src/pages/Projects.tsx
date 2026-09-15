import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Projects() {
  const { data: orgs } = useQuery({ queryKey:['orgs'], queryFn: async()=>(await api.get('/api/v1/organizations',{params:{size:20}})).data.data })
  const orgList = orgs?.content || []
  const orgId = orgList[0]?.id
  const { data, refetch } = useQuery({ queryKey:['projects', orgId], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:50}})).data.data, enabled: !!orgId })
  const [form, setForm] = useState({ name:'', description:'', criticality:'HIGH' })
  const [orgName, setOrgName] = useState('')

  async function createProject() {
    if (!orgId) return alert('Create org first')
    const wsRes = await api.get('/api/v1/workspaces', { params:{ organizationId: orgId, size: 1 } })
    let wsId = wsRes.data.data.content?.[0]?.id
    if (!wsId) {
      const ws = await api.post('/api/v1/workspaces', { name:'Primary', organizationId: orgId, environment:'PRODUCTION' })
      wsId = ws.data.data.id
    }
    await api.post('/api/v1/projects', { name: form.name, description: form.description, criticality: form.criticality, workspaceId: wsId, organizationId: orgId })
    setForm({ name:'', description:'', criticality:'HIGH' }); refetch()
  }
  async function createOrg() {
    await api.post('/api/v1/organizations', { name: orgName, description: 'Created via UI' })
    setOrgName(''); location.reload()
  }

  return (
    <div className="space-y-6">
      <div><h1 className="text-2xl font-bold">Organization & Project Hierarchy</h1><p className="text-sm text-slate-500">Organization → Business Unit → Team → Workspace → Project → Application / Repository / API / Mobile / Cloud</p></div>

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-3">Organizations</h3>
          {orgList.map((o:any)=><div key={o.id} className="border rounded-lg p-3 mb-2"><div className="font-medium text-sm">{o.name}</div><div className="text-xs text-slate-500">{o.slug} • {o.tier}</div></div>)}
          <div className="flex gap-2 mt-3">
            <input value={orgName} onChange={e=>setOrgName(e.target.value)} placeholder="New org name" className="flex-1 border rounded-lg px-3 py-2 text-sm" />
            <button onClick={createOrg} className="px-3 py-2 bg-slate-900 text-white rounded-lg text-sm">Create</button>
          </div>
        </div>
        <div className="lg:col-span-2 bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-3">Create Project</h3>
          <div className="grid md:grid-cols-3 gap-3">
            <input value={form.name} onChange={e=>setForm({...form,name:e.target.value})} placeholder="Project name (e.g. Digital Banking)" className="border rounded-lg px-3 py-2 text-sm" />
            <input value={form.description} onChange={e=>setForm({...form,description:e.target.value})} placeholder="Description" className="border rounded-lg px-3 py-2 text-sm" />
            <select value={form.criticality} onChange={e=>setForm({...form,criticality:e.target.value})} className="border rounded-lg px-3 py-2 text-sm"><option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option></select>
          </div>
          <button onClick={createProject} className="mt-3 px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm">Create Project</button>

          <div className="mt-6">
            <h4 className="text-sm font-semibold mb-2">Projects</h4>
            <div className="space-y-2">
              {(data?.content||[]).map((p:any)=>(
                <div key={p.id} className="border rounded-lg p-3 flex justify-between">
                  <div><div className="font-medium text-sm">{p.name}</div><div className="text-xs text-slate-500">{p.description} • {p.criticality} • {p.businessUnit || 'Retail'}</div></div>
                  <span className="text-xs bg-slate-100 border px-2 py-1 rounded h-fit">{p.status}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-2">Example Final Assessment (per PRD #142)</h3>
        <div className="grid md:grid-cols-3 gap-4 text-sm">
          <div className="bg-slate-50 rounded-lg p-4">
            <div className="font-semibold">Digital Banking</div>
            <div className="text-xs text-slate-500 mt-1">Android 1 • Backend 14 • Repos 18 • APIs 148 • Containers 31 • Cloud 214</div>
            <div className="mt-3 text-2xl font-bold">67 <span className="text-sm font-normal">/ 100</span></div>
            <div className="text-xs text-slate-500">Security Score</div>
          </div>
          <div className="bg-slate-50 rounded-lg p-4">
            <div className="font-semibold">Findings</div>
            <div className="mt-2 space-y-1 text-xs"><div>CRITICAL 3</div><div>HIGH 17</div><div>MEDIUM 42</div><div>LOW 71</div></div>
          </div>
          <div className="bg-slate-50 rounded-lg p-4">
            <div className="font-semibold">Priority #1</div>
            <div className="text-xs mt-1">Authorization weakness — Risk 94 • Payment API • Internet YES • Reachable YES</div>
            <div className="mt-2 text-xs bg-red-50 border border-red-200 rounded p-2">#2 Vulnerable Dependency CVSS 9.8 KEV YES • #3 Hardcoded Secret from APK</div>
          </div>
        </div>
      </div>
    </div>
  )
}
