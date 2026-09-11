import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../api/client'

type Platform = 'WEB' | 'API' | 'MOBILE' | 'REPO' | 'CONTAINER' | 'NETWORK'

export default function OneClickTest() {
  const [step, setStep] = useState<1|2|3>(1)
  const [projectId, setProjectId] = useState('')
  const [newProjectName, setNewProjectName] = useState('')
  const [platforms, setPlatforms] = useState<Platform[]>(['WEB'])
  const [targets, setTargets] = useState<Record<string, string[]>>({ WEB: [''], API: [''], REPO: [''], MOBILE: [''], CONTAINER: [''], NETWORK: [''] })
  const [runs, setRuns] = useState<any[]>([])
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState<any>(null)

  const { data: projects } = useQuery({ queryKey: ['projects'], queryFn: async () => (await api.get('/api/v1/projects', { params: { size: 50 } })).data.data })
  const projList = projects?.content || []

  function togglePlatform(p: Platform) {
    setPlatforms(prev => prev.includes(p) ? prev.filter(x => x !== p) : [...prev, p])
  }
  function updateTarget(p: string, idx: number, val: string) {
    setTargets(prev => {
      const arr = [...(prev[p] || [''])]
      arr[idx] = val
      return { ...prev, [p]: arr }
    })
  }
  function addTarget(p: string) {
    setTargets(prev => ({ ...prev, [p]: [...(prev[p] || []), ''] }))
  }
  function removeTarget(p: string, idx: number) {
    setTargets(prev => ({ ...prev, [p]: prev[p].filter((_, i) => i !== idx) }))
  }

  async function createProjectIfNeeded(): Promise<string> {
    if (projectId) return projectId
    if (!newProjectName.trim()) throw new Error('Pilih project atau buat baru')
    // need workspaceId/org - pick first workspace from first project or create minimal
    const wsRes = await api.get('/api/v1/workspaces', { params: { size: 1 } }).catch(() => ({ data: { data: { content: [] } } }))
    const ws = wsRes.data.data?.content?.[0]
    if (!ws) throw new Error('No workspace — buat org/workspace dulu di /projects')
    const res = await api.post('/api/v1/projects', { name: newProjectName.trim(), workspaceId: ws.id, organizationId: ws.organizationId, criticality: 'MEDIUM' })
    return res.data.data.id
  }

  async function start() {
    const effProject = await createProjectIfNeeded().catch(e => { alert(e.message); throw e })
    if (!effProject) return
    setProjectId(effProject)
    // collect all non-empty targets across selected platforms
    const allTargets: { platform: string, target: string }[] = []
    for (const p of platforms) {
      const list = targets[p] || []
      for (const t of list) if (t.trim()) allTargets.push({ platform: p, target: t.trim() })
    }
    if (allTargets.length === 0) return alert('Isi minimal 1 target (URL, repo, image, atau upload APK di langkah Mobile)')
    setRunning(true)
    setRuns([])
    setStep(3)
    const newRuns: any[] = []
    for (const item of allTargets) {
      try {
        // show current action
        setProgress({ message: `Menjalankan ${item.platform}: ${item.target} ...`, progress: 5, status: 'RUNNING', target: item.target, detectedType: item.platform })
        const res = await api.post('/api/v1/one-click/test', { target: item.target, projectId: effProject })
        const runId = res.data.data.id
        // poll progress for this run until done
        let prog: any = null
        for (let i = 0; i < 40; i++) {
          await new Promise(r => setTimeout(r, 2000))
          prog = (await api.get(`/api/v1/one-click/${runId}/progress`)).data.data
          setProgress({ ...prog, currentTarget: item.target, queue: `${newRuns.length + 1}/${allTargets.length}` })
          setRuns(prev => {
            const copy = [...prev]
            const idx = copy.findIndex(x => x.id === runId)
            if (idx >= 0) copy[idx] = prog
            else copy.push(prog)
            return copy
          })
          if (prog.status === 'COMPLETED' || prog.status === 'FAILED') break
        }
        newRuns.push(prog || { target: item.target, platform: item.platform, status: 'UNKNOWN' })
      } catch (e: any) {
        newRuns.push({ target: item.target, platform: item.platform, status: 'FAILED', message: e.response?.data?.message || e.message })
      }
    }
    setRunning(false)
    setProgress({ message: `Selesai ${newRuns.length} target — ${newRuns.reduce((a, r) => a + (r.findingsCount || 0), 0)} temuan`, status: 'COMPLETED', progress: 100 })
  }

  const totalFindings = runs.reduce((a, r) => a + (r.findingsCount || 0), 0)

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="bg-gradient-to-br from-indigo-600 to-violet-600 rounded-2xl p-6 md:p-8 text-white">
        <h1 className="text-2xl md:text-3xl font-bold">Test Platform Apa Saja — 1 Klik</h1>
        <p className="text-indigo-100 mt-2 text-sm">Daftar project → pilih platform → masukkan target (bisa banyak) → 1 klik jalankan semua serangan (42 jenis) → progress live → report</p>
        <div className="flex gap-2 mt-3 text-xs">
          <span className={`px-2.5 py-1 rounded-full ${step===1?'bg-white text-indigo-600':'bg-indigo-500 text-white'}`}>1. Project</span>
          <span className={`px-2.5 py-1 rounded-full ${step===2?'bg-white text-indigo-600':'bg-indigo-500 text-white'}`}>2. Platform & Target</span>
          <span className={`px-2.5 py-1 rounded-full ${step===3?'bg-white text-indigo-600':'bg-indigo-500 text-white'}`}>3. Run & Report</span>
        </div>
      </div>

      {step === 1 && (
        <div className="bg-white border rounded-2xl p-6 space-y-4">
          <h3 className="font-semibold">Langkah 1 — Pilih / Buat Project</h3>
          <select value={projectId} onChange={e => { setProjectId(e.target.value); setNewProjectName('') }} className="w-full border rounded-xl px-4 py-3 text-sm">
            <option value="">-- Pilih project existing --</option>
            {projList.map((p: any) => <option key={p.id} value={p.id}>{p.name} — {p.id.slice(0,8)}</option>)}
          </select>
          <div className="text-center text-xs text-slate-400">atau</div>
          <input value={newProjectName} onChange={e => { setNewProjectName(e.target.value); setProjectId('') }} placeholder="Nama project baru (mis: DSRV Web)" className="w-full border rounded-xl px-4 py-3 text-sm" />
          <div className="flex gap-3">
            <button onClick={() => setStep(2)} disabled={!projectId && !newProjectName.trim()} className="ml-auto bg-indigo-600 text-white px-6 py-2.5 rounded-xl text-sm font-medium disabled:opacity-50">Lanjut → Platform</button>
          </div>
          <div className="text-xs text-slate-500">Project = wadah untuk semua asset & findings. Pilih platform di langkah berikut.</div>
        </div>
      )}

      {step === 2 && (
        <div className="bg-white border rounded-2xl p-6 space-y-5">
          <h3 className="font-semibold">Langkah 2 — Pilih Platform & Masukkan Target (bisa banyak)</h3>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {(['WEB','API','MOBILE','REPO','CONTAINER','NETWORK'] as Platform[]).map(p => (
              <label key={p} className={`border rounded-xl p-3 flex items-center gap-2 cursor-pointer ${platforms.includes(p) ? 'bg-indigo-50 border-indigo-300' : 'bg-white'}`}>
                <input type="checkbox" checked={platforms.includes(p)} onChange={() => togglePlatform(p)} />
                <span className="text-sm font-medium">{p}</span>
                <span className="text-xs text-slate-500 ml-auto">{p==='WEB'?'domain/url': p==='API'?'endpoint': p==='MOBILE'?'APK/IPA': p==='REPO'?'git url': p==='CONTAINER'?'image:tag':'IP/host'}</span>
              </label>
            ))}
          </div>

          {platforms.map(p => (
            <div key={p} className="border rounded-xl p-4 space-y-2">
              <div className="font-medium text-sm">{p} — Target {p==='API' || p==='WEB' ? '(bisa banyak, + tambah)' : p==='MOBILE' ? '(upload APK)' : ''}</div>
              {(targets[p] || ['']).map((val, idx) => (
                <div key={idx} className="flex gap-2">
                  {p==='MOBILE' ? (
                    <input type="file" accept=".apk,.aab,.ipa" onChange={async e => {
                      const file = e.target.files?.[0]
                      if (!file) return
                      // upload via mobile endpoint, use file name as target for now
                      updateTarget(p, idx, file.name)
                      // real upload would POST /api/v1/mobile/upload
                    }} className="flex-1 border rounded-lg px-3 py-2 text-sm" />
                  ) : (
                    <input value={val} onChange={e => updateTarget(p, idx, e.target.value)} placeholder={p==='WEB'?'https://dsrv-developer.my.id/': p==='API'?'https://api.acme.com/v1/users': p==='REPO'?'github.com/acme/app': p==='CONTAINER'?'nginx:1.25': '192.168.1.10'} className="flex-1 border rounded-lg px-3 py-2 text-sm" />
                  )}
                  <button onClick={() => removeTarget(p, idx)} className="px-2 text-slate-400 hover:text-red-600">×</button>
                </div>
              ))}
              <button onClick={() => addTarget(p)} className="text-xs text-indigo-600 hover:underline">+ Tambah {p} target</button>
            </div>
          ))}

          <div className="flex gap-3">
            <button onClick={() => setStep(1)} className="px-4 py-2 border rounded-xl text-sm">← Kembali</button>
            <button onClick={start} disabled={running} className="ml-auto bg-indigo-600 text-white px-8 py-2.5 rounded-xl text-sm font-semibold disabled:opacity-50">▶ Test Sekarang (1 Klik) — {platforms.length} platform, {Object.values(targets).flat().filter(v=>v.trim()).length} target</button>
          </div>
          <div className="text-xs text-slate-400">Sistem auto-detect + jalankan 8 scanner (SAST, SCA, Secrets, DAST, API, Container, IAC, Mobile) paralel per target. Semua serangan di tabel kamu (42 jenis) dicover via SAST pattern + DAST live fetch.</div>
        </div>
      )}

      {step === 3 && (
        <div className="bg-white border rounded-2xl p-6 space-y-4">
          <div className="flex justify-between items-center">
            <h3 className="font-semibold">Progress Live — Sedang melakukan apa</h3>
            <span className={`text-xs px-2.5 py-1 rounded-full ${progress?.status==='COMPLETED'?'bg-emerald-100 text-emerald-700':'bg-amber-100 text-amber-700 animate-pulse'}`}>{progress?.status || 'RUNNING'} {progress?.progress ?? 5}%</span>
          </div>
          <div className="w-full bg-slate-100 rounded-full h-3 overflow-hidden"><div className="h-full bg-indigo-600 transition-all" style={{ width: `${progress?.progress ?? 5}%` }} /></div>
          <div className="bg-slate-50 border rounded-xl p-3 text-sm">
            <div className="font-medium text-indigo-700">📌 {progress?.currentAction || progress?.message || 'Menyiapkan scanner & antrian Kafka...'}</div>
            <div className="text-xs text-slate-500 mt-1">{progress?.message}</div>
            {progress?.queue && <div className="text-xs text-slate-400">Antrean: {progress.queue}</div>}
          </div>

          {runs.length > 0 && (
            <div className="space-y-2">
              <div className="text-sm font-medium">Per Target:</div>
              {runs.map((r: any) => (
                <div key={r.id || r.target} className="border rounded-xl p-3 flex justify-between items-center">
                  <div><div className="font-medium text-sm">{r.target} <span className="text-xs bg-slate-100 px-1.5 py-0.5 rounded ml-2">{r.detectedType || r.platform}</span></div><div className="text-xs text-slate-500">{r.message || r.status}</div></div>
                  <div className="text-right"><div className="text-xs px-2 py-1 rounded bg-slate-100">{r.status} {r.progress || 0}%</div><div className="text-xs text-slate-500">{r.findingsCount ?? 0} temuan</div></div>
                </div>
              ))}
              <div className="text-sm font-semibold">Total temuan: {totalFindings} — <a href="/findings" className="text-indigo-600 hover:underline">Lihat Findings</a> • <a href="/reports" className="text-indigo-600 hover:underline">Lihat Report</a></div>
            </div>
          )}

          {!running && progress?.status==='COMPLETED' && (
            <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-4 text-sm text-emerald-800">
              ✅ Selesai — {totalFindings} temuan dari {runs.length} target. Report otomatis dibuat. <a href="/reports" className="font-semibold underline">Buka Report</a> atau <a href="/findings" className="underline">cek Findings</a>. Menu lain (Mobile RE, Graph, Threat Model, Compliance) di sidebar Advanced untuk drill-down.
            </div>
          )}
        </div>
      )}
    </div>
  )
}
