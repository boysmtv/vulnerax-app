import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'
import { useState } from 'react'

export default function Mobile() {
  const [projectId, setProjectId] = useState('')
  const [fileName, setFileName] = useState('app-release.apk')
  const [platform, setPlatform] = useState('ANDROID')
  const { data: projects } = useQuery({ queryKey:['projects'], queryFn: async()=>(await api.get('/api/v1/projects',{params:{size:20}})).data.data })
  const projList = projects?.content || []
  const eff = projectId || projList[0]?.id
  const { data, refetch } = useQuery({ queryKey:['mobile', eff], queryFn: async()=>(await api.get('/api/v1/mobile',{params:{projectId: eff}})).data.data, enabled: !!eff })
  const [selected, setSelected] = useState<any>(null)
  const [ws, setWs] = useState<any>(null)

  async function upload() {
    await api.post('/api/v1/mobile/upload', null, { params:{ projectId: eff, fileName, platform } })
    refetch()
  }
  async function openWs(id: string) {
    const r = await api.get(`/api/v1/mobile/${id}/workspace`)
    setWs(r.data.data)
    setSelected(id)
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-end">
        <div><h1 className="text-2xl font-bold">Mobile Security & Reverse Engineering</h1><p className="text-sm text-slate-500">APK / AAB / IPA • MASVS / MASWE / MASTG • JADX / APKTool / MobSF / Ghidra</p></div>
        <select value={eff} onChange={e=>setProjectId(e.target.value)} className="border rounded-lg px-3 py-2 text-sm">
          {projList.map((p:any)=><option key={p.id} value={p.id}>{p.name}</option>)}
        </select>
      </div>

      <div className="bg-white border rounded-xl p-5">
        <h3 className="font-semibold text-sm mb-3">Upload Artifact</h3>
        <div className="flex gap-3">
          <input value={fileName} onChange={e=>setFileName(e.target.value)} className="border rounded-lg px-3 py-2 text-sm flex-1" placeholder="app.apk / app.aab / app.ipa" />
          <select value={platform} onChange={e=>setPlatform(e.target.value)} className="border rounded-lg px-3 py-2 text-sm"><option>ANDROID</option><option>IOS</option></select>
          <button onClick={upload} className="bg-indigo-600 text-white px-4 py-2 rounded-lg text-sm">Analyze</button>
        </div>
        <div className="text-xs text-slate-500 mt-2">Checks: exported components, permissions, deep links, backup, cleartext, WebView JS bridge, crypto, storage, keystore, cert pinning, obfuscation, native libs</div>
      </div>

      <div className="grid lg:grid-cols-3 gap-4">
        <div className="bg-white border rounded-xl p-5">
          <h3 className="font-semibold text-sm mb-3">Artifacts</h3>
          <div className="space-y-2">
            {(Array.isArray(data)? data: []).map((m:any)=>(
              <div key={m.id} onClick={()=>openWs(m.id)} className={`border rounded-lg p-3 cursor-pointer hover:bg-slate-50 ${selected===m.id?'ring-2 ring-indigo-500':''}`}>
                <div className="font-medium text-sm">{m.fileName}</div>
                <div className="text-xs text-slate-500">{m.platform} • {m.masvsScore}/100 MASVS • {m.status}</div>
                <div className="text-xs text-slate-400">{m.fileSha256?.substring(0,16)} • {(m.fileSize/1024/1024).toFixed(1)} MB</div>
              </div>
            ))}
            {(!data || (Array.isArray(data) && data.length===0)) && <div className="text-sm text-slate-500">No artifacts. Upload APK to see Reverse Engineering Workspace.</div>}
          </div>
        </div>
        <div className="lg:col-span-2">
          {ws ? (
            <div className="space-y-4">
              <div className="bg-white border rounded-xl p-5">
                <h3 className="font-semibold text-sm mb-3">Overview • Manifest • Strings • Classes • Libraries • Endpoints • Crypto • Certificates • Call Graph • Files • Findings</h3>
                <div className="grid md:grid-cols-2 gap-4 text-sm">
                  <div><div className="font-medium">Overview</div><pre className="bg-slate-900 text-slate-100 p-3 rounded text-xs mt-1 overflow-auto">{JSON.stringify(ws.overview, null, 2)}</pre></div>
                  <div><div className="font-medium">Manifest</div><pre className="bg-slate-50 border p-3 rounded text-xs mt-1 overflow-auto h-40">{ws.manifest}</pre></div>
                </div>
                <div className="mt-4"><div className="font-medium text-sm">Endpoints</div><div className="flex flex-wrap gap-2 mt-1">{(ws.endpoints||[]).map((e:string)=><span key={e} className="text-xs bg-indigo-50 border border-indigo-200 px-2 py-1 rounded">{e}</span>)}</div></div>
                <div className="mt-4"><div className="font-medium text-sm">MASVS Mapping</div><div className="space-y-1 mt-2">{(ws.masvs||[]).map((c:any)=><div key={c.control} className="flex justify-between text-xs border rounded p-2"><span>{c.control}</span><span className={c.status==='FAIL'?'text-red-600':'text-emerald-600'}>{c.status} • {c.severity}</span></div>)}</div></div>
              </div>
              <div className="bg-white border rounded-xl p-5">
                <h3 className="font-semibold text-sm mb-2">Call Graph / Control Flow (simplified)</h3>
                <pre className="text-xs bg-slate-900 text-slate-100 p-4 rounded-lg overflow-auto">{(ws.callGraph||[]).join('\n')}</pre>
              </div>
            </div>
          ) : (
            <div className="bg-white border rounded-xl p-12 text-center text-sm text-slate-500">Select an artifact to view Reverse Engineering Workspace</div>
          )}
        </div>
      </div>
    </div>
  )
}
