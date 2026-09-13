import { useState } from 'react'
import { api } from '../api/client'
import { useAuth } from '../store/auth'
import { useNavigate, Link } from 'react-router-dom'
import { Shield } from 'lucide-react'

export default function Login() {
  const [email, setEmail] = useState('admin@vulnerax.io')
  const [password, setPassword] = useState('Admin123!')
  const [mode, setMode] = useState<'login'|'register'>('login')
  const [fullName, setFullName] = useState('Demo User')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const { login } = useAuth()
  const nav = useNavigate()

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(''); setLoading(true)
    try {
      const url = mode === 'login' ? '/api/v1/auth/login' : '/api/v1/auth/register'
      const payload = mode === 'login' ? { email, password } : { email, password, fullName, name: fullName, role: 'SECURITY_ENGINEER' }
      const res = await api.post(url, payload)
      const data = res.data.data
      login(data.accessToken || data.token, data.user)
      nav('/')
    } catch (err: any) {
      setError(err.response?.data?.message || err.message)
    } finally { setLoading(false) }
  }

  return (
    <div className="min-h-screen flex">
      <div className="flex-1 flex items-center justify-center p-8 bg-white">
        <form onSubmit={submit} className="w-full max-w-sm space-y-6">
          <div className="flex items-center gap-3">
            <div className="bg-indigo-600 p-2.5 rounded-xl"><Shield className="text-white" /></div>
            <div><h1 className="text-xl font-bold">VulneraX</h1><p className="text-xs text-slate-500">Unified Security Platform</p></div>
          </div>
          <div>
            <h2 className="text-2xl font-semibold">{mode==='login'?'Welcome back':'Create account'}</h2>
            <p className="text-sm text-slate-500 mt-1">Demo: admin@vulnerax.io / Admin123! &nbsp; • &nbsp; dev@vulnerax.io / Dev123!</p>
          </div>
          {error && <div className="bg-red-50 text-red-700 text-sm p-3 rounded-lg border border-red-200">{error}</div>}
          <div className="space-y-3">
            {mode==='register' && <input value={fullName} onChange={e=>setFullName(e.target.value)} placeholder="Full name" className="w-full border rounded-lg px-3 py-2.5 text-sm" />}
            <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="Email" className="w-full border rounded-lg px-3 py-2.5 text-sm" />
            <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" className="w-full border rounded-lg px-3 py-2.5 text-sm" />
          </div>
          <button disabled={loading} className="w-full bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg py-2.5 text-sm font-medium disabled:opacity-50">{loading?'Please wait...': mode==='login'?'Sign in':'Create account'}</button>
          <p className="text-sm text-center text-slate-500">
            {mode==='login' ? <>No account? <button type="button" onClick={()=>setMode('register')} className="text-indigo-600 font-medium">Register</button></> : <>Have account? <button type="button" onClick={()=>setMode('login')} className="text-indigo-600 font-medium">Login</button></>}
          </p>
          <div className="pt-4 border-t text-xs text-slate-400 space-y-1">
            <div>• SAST • SCA • Secrets • DAST • API • Mobile • Container • Cloud • IaC</div>
            <div>• Risk Engine (CVSS+EPSS+KEV) • Attack Path • AI Analyst • SBOM</div>
          </div>
        </form>
      </div>
      <div className="hidden lg:flex flex-1 bg-slate-900 text-white p-12 flex-col justify-between">
        <div />
        <div className="space-y-6">
          <h2 className="text-3xl font-bold leading-tight">Security Control Plane<br/>+ Scanner Orchestrator<br/>+ Risk Intelligence</h2>
          <p className="text-slate-300 leading-relaxed">One platform to Discover → Assess → Correlate → Prioritize → Remediate → Verify → Monitor → Report across 50+ asset types.</p>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div className="bg-slate-800 rounded-lg p-3">Security Score<br/><span className="text-2xl font-bold text-emerald-400">74 / 100</span></div>
            <div className="bg-slate-800 rounded-lg p-3">Critical Risk<br/><span className="text-2xl font-bold text-red-400">3</span> internet-exposed</div>
          </div>
        </div>
        <div className="text-xs text-slate-500">© 2026 VulneraX • OWASP Top 10 2025 • ASVS 5.0 • CVSS 4.0 • SARIF 2.1 • MASVS</div>
      </div>
    </div>
  )
}
