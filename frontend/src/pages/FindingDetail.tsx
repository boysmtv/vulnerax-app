import { useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function FindingDetail() {
  const { id } = useParams()
  const { data } = useQuery({ queryKey: ['finding', id], queryFn: async () => (await api.get(`/api/v1/findings/${id}`)).data.data, enabled: !!id })
  const { data: ai } = useQuery({ queryKey: ['ai', id], queryFn: async () => (await api.get(`/api/v1/ai/explain/${id}`)).data.data, enabled: !!id })
  const { data: ev } = useQuery({ queryKey: ['ev', id], queryFn: async () => (await api.get(`/api/v1/findings/${id}/evidence`)).data.data, enabled: !!id })
  const { data: corr } = useQuery({ queryKey: ['corr', id], queryFn: async () => (await api.get(`/api/v1/findings/${id}/correlation`)).data.data, enabled: !!id })
  const [tab, setTab] = useState('overview')
  if (!data) return <div className="text-sm text-slate-500">Loading...</div>
  return (
    <div className="space-y-6">
      <div className="bg-white rounded-xl border p-6">
        <div className="flex flex-wrap justify-between gap-4">
          <div>
            <div className="text-xs text-slate-500">{data.findingId} • {data.cwe} • {data.owasp} • {data.source}</div>
            <h1 className="text-xl font-bold mt-1">{data.title}</h1>
            <p className="text-sm text-slate-600 mt-2 max-w-3xl">{data.description}</p>
          </div>
          <div className="text-right">
            <div className="text-xs text-slate-500">Contextual Risk</div>
            <div className="text-3xl font-bold text-red-600">{data.riskScore} <span className="text-sm font-normal text-slate-500">/ 100 • {data.riskLevel}</span></div>
            <div className="text-xs mt-1">CVSS {data.cvss} • EPSS {data.epss?.toFixed(2)} {data.kev && <span className="bg-red-100 text-red-700 px-2 py-0.5 rounded">KEV</span>}</div>
            <div className="text-xs text-slate-500 mt-1">SLA {data.slaStatus} • Due {data.slaDueAt ? new Date(data.slaDueAt).toLocaleDateString() : '-'}</div>
          </div>
        </div>
        <div className="mt-4 flex gap-2 text-xs">
          <span className="px-2 py-1 bg-slate-900 text-white rounded">{data.severity}</span>
          <span className="px-2 py-1 bg-slate-100 border rounded">{data.confidence} confidence</span>
          <span className="px-2 py-1 bg-slate-100 border rounded">{data.status}</span>
          {data.internetExposed && <span className="px-2 py-1 bg-orange-100 text-orange-700 border border-orange-200 rounded">Internet Exposed</span>}
          {data.reachable && <span className="px-2 py-1 bg-amber-100 text-amber-700 border rounded">Reachable</span>}
        </div>
      </div>

      <div className="flex gap-2 border-b text-sm">
        {['overview','code','evidence','correlation','ai'].map(t=>(
          <button key={t} onClick={()=>setTab(t)} className={`px-4 py-2 border-b-2 capitalize ${tab===t?'border-indigo-600 text-indigo-600 font-medium':'border-transparent text-slate-500'}`}>{t}</button>
        ))}
      </div>

      {tab==='overview' && (
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 space-y-4">
            <div className="bg-white rounded-xl border p-5">
              <h3 className="font-semibold text-sm mb-2">What happened? Where? Why?</h3>
              <div className="text-sm space-y-2">
                <div><span className="text-slate-500">Asset:</span> {data.assetName} ({data.environment}) • Owner {data.owner}</div>
                <div><span className="text-slate-500">Location:</span> {data.filePath}:{data.lineNumber} • {data.functionName}</div>
                <div><span className="text-slate-500">Data flow:</span> {data.dataFlow}</div>
                <div><span className="text-slate-500">How dangerous:</span> Risk {data.riskScore} — Business criticality {data.businessCriticality} {data.internetExposed?'• Internet exposed':''}</div>
                <div><span className="text-slate-500">How to verify:</span> Retest scan / DAST authenticated replay</div>
              </div>
            </div>
            <div className="bg-white rounded-xl border p-5">
              <h3 className="font-semibold text-sm mb-2">Recommendation</h3>
              <p className="text-sm text-slate-700">{data.recommendation}</p>
              {data.codeSnippet && <pre className="mt-3 bg-slate-900 text-slate-100 p-3 rounded-lg text-xs overflow-auto">{data.codeSnippet}</pre>}
            </div>
          </div>
          <div className="space-y-4">
            <div className="bg-white rounded-xl border p-5">
              <h3 className="font-semibold text-sm mb-3">AI Security Analyst</h3>
              {ai ? (
                <div className="space-y-3 text-sm">
                  <div><span className="font-medium">Root Cause:</span><p className="text-slate-600">{ai.rootCause}</p></div>
                  <div><span className="font-medium">Impact:</span><p className="text-slate-600">{ai.impact}</p></div>
                  <div><span className="font-medium">Fix:</span><p className="text-slate-600">{ai.remediation}</p></div>
                  <pre className="bg-slate-900 text-slate-100 p-3 rounded text-xs overflow-auto">{ai.codeFix}</pre>
                  <div className="text-xs bg-indigo-50 border border-indigo-200 rounded p-2">Priority: {ai.priority}</div>
                </div>
              ) : <div className="text-sm text-slate-500">Loading AI analysis...</div>}
            </div>
            <div className="bg-white rounded-xl border p-5">
              <h3 className="font-semibold text-sm mb-2">Fingerprint (Dedup)</h3>
              <code className="text-xs bg-slate-100 p-2 rounded block break-all">{data.fingerprint}</code>
              <p className="text-xs text-slate-500 mt-2">Shares fingerprint with instances grouped under parent. Suppression requires reason + approver + expiration.</p>
            </div>
          </div>
        </div>
      )}
      {tab==='code' && (
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">Code Path & Evidence</h3>
          <div className="text-sm space-y-2"><div>File: <code>{data.filePath}:{data.lineNumber}</code></div><div>Function: {data.functionName}</div><div>Call chain: Controller → Service → Repository</div></div>
          <pre className="mt-4 bg-slate-900 text-slate-100 p-4 rounded-lg text-xs overflow-auto">{data.codeSnippet || '// no snippet'}</pre>
          <div className="mt-3 text-xs text-slate-500">Stack trace, HTTP request/response available in Evidence tab.</div>
        </div>
      )}
      {tab==='evidence' && (
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">Evidence (hash, timestamp, chain of custody)</h3>
          {(ev||[]).map((e:any)=>(
            <div key={e.id} className="border rounded-lg p-3 mb-2 text-sm">
              <div className="font-medium">{e.type} • {e.sha256?.substring(0,12)}</div>
              <div className="text-slate-600 text-xs">{e.content}</div>
              <div className="text-xs text-slate-400">{new Date(e.createdAt).toLocaleString()} • {e.author}</div>
            </div>
          ))}
          {(!ev || ev.length===0) && <div className="text-sm text-slate-500">No evidence yet.</div>}
        </div>
      )}
      {tab==='correlation' && (
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">Cross-Scanner Correlation</h3>
          <p className="text-sm text-slate-600">SAST + DAST + Asset exposure fused into confirmed high-risk. {corr?.attackPathCandidate}</p>
          <div className="mt-4 space-y-2">
            {(corr?.correlated||[]).map((c:any)=>(
              <div key={c.id} className="border rounded-lg p-3 text-sm"><div className="font-medium">{c.title}</div><div className="text-xs text-slate-500">{c.severity} • {c.type} • {c.assetName}</div></div>
            ))}
            {(!corr?.correlated || corr.correlated.length===0) && <div className="text-sm text-slate-500">No correlated findings on this asset yet.</div>}
          </div>
        </div>
      )}
      {tab==='ai' && (
        <div className="bg-white rounded-xl border p-5">
          <h3 className="font-semibold text-sm mb-3">AI Fix Assistant</h3>
          {ai && <div className="space-y-3 text-sm">
            <div><b>What is wrong:</b> {ai.summary}</div>
            <div><b>Why it matters:</b> {ai.impact}</div>
            <div><b>Recommended design change:</b> {ai.remediation}</div>
            <div><b>Affected components:</b> {data.assetName}, {data.filePath}</div>
            <div><b>Test recommendation:</b> {ai.testRecommendation}</div>
            <div><b>Regression risk:</b> Medium — validate auth flows</div>
          </div>}
        </div>
      )}
    </div>
  )
}
