import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Graph() {
  const [projectId, setProjectId] = useState('')
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:20}})).data.data })
  const projList = projects?.content || []
  const eff = projectId || projList[0]?.id
  const { data } = useQuery({ queryKey:['graph', eff], queryFn: async()=>(await api.get('/api/v1/graph',{params:{projectId: eff}})).data.data, enabled: !!eff })
  const { data: paths } = useQuery({ queryKey:['paths', eff], queryFn: async()=>(await api.get('/api/v1/graph/attack-paths',{params:{projectId: eff}})).data.data, enabled: !!eff })

  const nodes = data?.nodes || []
  const edges = data?.edges || []

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-end">
        <div><h1 className="text-2xl font-bold">Security Graph & Attack Path</h1><p className="text-sm text-slate-500">Asset → Component → Dependency → API → Identity → Vulnerability — Unified graph answers "what can it affect?"</p></div>
        <select value={eff} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
          {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-3">Attack Graph (interactive — click node for asset • exposure • finding • controls)</h3>
          <div className="bg-slate-900 rounded-lg p-4 min-h-[380px] overflow-auto">
            <div className="text-xs text-slate-400 mb-3">Nodes: {nodes.length} • Edges: {edges.length} • Stats: {JSON.stringify(data?.stats || {})}</div>
            <div className="space-y-3">
              <div className="flex flex-wrap gap-2">
                {nodes.slice(0,12).map((n:any)=>(
                  <div key={n.id} className={`px-3 py-2 rounded-lg text-xs border ${n.type==='FINDING' ? (n.severity==='CRITICAL'?'bg-red-600 text-white border-red-700': n.severity==='HIGH'?'bg-orange-500 text-white':'bg-amber-400') : 'bg-slate-800 text-slate-100 border-slate-700'}`}>
                    <div className="font-medium">{n.label}</div><div className="opacity-70">{n.type} {n.assetType||n.severity||''}</div>
                  </div>
                ))}
              </div>
              <div className="text-xs text-slate-500 font-mono">
                {edges.slice(0,10).map((e:any, i:number)=><div key={i}>{e.from.substring(0,8)} —[{e.label}]→ {e.to.substring(0,8)}</div>)}
                {edges.length>10 && <div>... +{edges.length-10} more edges</div>}
              </div>
              <div className="mt-4 p-3 bg-slate-800 rounded text-xs text-slate-300">
                Example path:<br/>
                Internet → api.acme.com → API Gateway → payment-service (vulnerable log4j CVE-2021-44228, KEV) → PostgreSQL (transactions) → Sensitive Data<br/>
                Trust relationships & blast radius derived from graph.
              </div>
            </div>
          </div>
        </div>
        <div className="bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-3">Attack Paths (Entry Point → Affected Assets → Weaknesses → Impact)</h3>
          <div className="space-y-3">
            {(Array.isArray(paths)? paths: []).map((p:any)=>(
              <div key={p.id} className="border rounded-lg p-3">
                <div className="text-xs text-slate-500">Entry: {p.entryPoint}</div>
                <div className="font-medium text-sm mt-1">{p.weakness}</div>
                <div className="text-xs text-slate-600">Asset: {p.asset} • Risk {p.risk} ({p.riskLevel})</div>
                <div className="mt-2 flex flex-wrap gap-1">{(p.chain||[]).map((c:string)=><span key={c} className="text-[10px] bg-slate-100 border px-1.5 py-0.5 rounded">{c}</span>)}</div>
                <div className="text-xs mt-2"><span className="font-medium">Impact:</span> {p.impact}</div>
                <div className="text-xs"><span className="font-medium">Mitigation:</span> {p.mitigation}</div>
              </div>
            ))}
            {(!paths || (Array.isArray(paths) && paths.length===0)) && <div className="text-sm text-slate-500">No attack paths yet. Generate findings with exposed assets to see paths.</div>}
          </div>
          <div className="mt-4 text-xs bg-indigo-50 border border-indigo-200 rounded p-3 text-indigo-800">Platform does not do uncontrolled autonomous exploitation. Paths are evidence-based correlation.</div>
        </div>
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-2">Security Knowledge Graph Relationships</h3>
        <pre className="text-xs bg-slate-50 border p-4 rounded-lg overflow-auto">{`APPLICATION USES REPOSITORY
REPOSITORY BUILDS ARTIFACT
ARTIFACT CONTAINS COMPONENT
COMPONENT HAS VULNERABILITY
APPLICATION EXPOSES API
API CALLS SERVICE
SERVICE CONNECTS DATABASE
IDENTITY CAN_ACCESS RESOURCE
Android App ─calls→ Payment API ─auth→ Identity Service ─access→ Payment Service ─writes→ Transaction DB`}</pre>
      </div>
    </div>
  )
}
