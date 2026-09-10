import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Compliance() {
  const [projectId, setProjectId] = useState('')
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:20}})).data.data })
  const projList = (projects as any)?.content || []
  const eff = projectId || (projList[0] as any)?.id
  const { data, refetch, isLoading } = useQuery({
    queryKey:['compliance/frameworks', eff],
    queryFn: async()=> (await api.get('/api/v1/compliance/frameworks', { params: { projectId: eff, organizationId: eff } })).data.data,
    enabled: !!eff
  })
  const list = Array.isArray(data) ? data : (data as any)?.content || []

  async function create(){
    try {
      await api.post('/api/v1/compliance/frameworks', { projectId: eff, organizationId: eff, name: 'demo-'+Date.now(), provider: 'AWS', type: 'SCM', channel: 'SLACK', recipient: 'sec@vulnerax.io', subject: 'Test', body: 'Demo', domain: 'SAST', status: 'TESTED', coveragePercent: 85, artifactName: 'app', version: '1.0', filePath: 'Dockerfile', host: '10.0.0.1', port: 443, platform: 'GITHUB_ACTIONS', repository: 'acme/app', pipelineName: 'ci', principalType: 'User', principalName: 'alice', manifestJson: '{}', fileName: 'firmware.bin', model: 'gpt-4' })
      refetch()
    } catch(e:any){ alert(e.response?.data?.message || e.message) }
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-end">
        <div><h1 className="text-2xl font-bold">Compliance Center</h1><p className="text-sm text-slate-500">Framework â†’ Control â†’ Requirement â†’ Test â†’ Evidence â†’ Finding</p></div>
        <div className="flex gap-2">
          <select value={eff as string} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
            {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
          </select>
          <button onClick={create} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm">Create Demo</button>
        </div>
      </div>
      {isLoading ? <div className="text-sm text-slate-500">Loading...</div> : (
        <div className="bg-white border rounded-xl overflow-hidden">
          <div className="overflow-x-auto max-h-[60vh]">
            <pre className="text-xs p-4 whitespace-pre-wrap break-words">{JSON.stringify(list.slice(0,3), null, 2) || 'No data yet. Click Create Demo or run a scan.'}</pre>
          </div>
          {list.length===0 && <div className="p-8 text-center text-sm text-slate-500">No data â€” Compliance Center will appear here after sync/scan.</div>}
          <div className="p-3 text-xs text-slate-500 border-t bg-slate-50">API: GET /api/v1/compliance/frameworks â€¢ POST â€¢ GET /{'{id}'} â€¢ Auto-mapped to PRD â€¢ Compliance Center</div>
        </div>
      )}
    </div>
  )
}
