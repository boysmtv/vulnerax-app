import { Link, useLocation, useNavigate } from 'react-router-dom'
import { Shield, LayoutDashboard, Boxes, Bug, Scan, FolderKanban, Smartphone, Network, FileText, Search, LogOut, Menu, ShieldAlert, ClipboardCheck, Gavel, Repeat, Cloud, Hexagon, FileCode, Database, GitBranch, KeyRound, Box, Bot, Puzzle, Cpu, Plug, Bell, PieChart, Flag, PackageCheck, Crosshair } from 'lucide-react'
import { useAuth } from '../store/auth'
import { useState } from 'react'

const nav = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/projects', label: 'Projects', icon: FolderKanban },
  { to: '/assets', label: 'Assets', icon: Boxes },
  { to: '/findings', label: 'Findings', icon: Bug },
  { to: '/scans', label: 'Scans', icon: Scan },
  { to: '/mobile', label: 'Mobile RE', icon: Smartphone },
  { to: '/graph', label: 'Attack Graph', icon: Network },
  { to: '/threat-model', label: 'Threat Model', icon: ShieldAlert },
  { to: '/pentest', label: 'Pentest', icon: Crosshair },
  { to: '/compliance', label: 'Compliance', icon: ClipboardCheck },
  { to: '/policies', label: 'Policies', icon: Gavel },
  { to: '/retest', label: 'Retest', icon: Repeat },
  { to: '/cloud', label: 'Cloud', icon: Cloud },
  { to: '/k8s', label: 'K8s', icon: Hexagon },
  { to: '/iac', label: 'IaC', icon: FileCode },
  { to: '/network', label: 'Network', icon: Network },
  { to: '/databases', label: 'Databases', icon: Database },
  { to: '/cicd', label: 'CI/CD', icon: GitBranch },
  { to: '/iam', label: 'IAM', icon: KeyRound },
  { to: '/containers', label: 'Containers', icon: Box },
  { to: '/ai-llm', label: 'AI/LLM', icon: Bot },
  { to: '/browser', label: 'Browser Ext', icon: Puzzle },
  { to: '/firmware', label: 'Firmware', icon: Cpu },
  { to: '/integrations', label: 'Integrations', icon: Plug },
  { to: '/notifications', label: 'Notifications', icon: Bell },
  { to: '/coverage', label: 'Coverage', icon: PieChart },
  { to: '/campaigns', label: 'Campaigns', icon: Flag },
  { to: '/supply-chain', label: 'Supply Chain', icon: PackageCheck },
  { to: '/reports', label: 'Reports', icon: FileText },
]

export default function Layout({ children }: { children: React.ReactNode }) {
  const { pathname } = useLocation()
  const { user, logout } = useAuth()
  const nav2 = useNavigate()
  const [open, setOpen] = useState(false)
  return (
    <div className="min-h-screen flex bg-slate-50">
      <aside className={`bg-slate-900 text-slate-200 w-64 shrink-0 flex flex-col ${open ? 'fixed inset-y-0 left-0 z-50' : 'hidden md:flex'}`}>
        <div className="p-6 flex items-center gap-3 border-b border-slate-800">
          <div className="bg-indigo-600 p-2 rounded-lg"><Shield size={20} className="text-white" /></div>
          <div><div className="font-bold text-white tracking-tight">VulneraX</div><div className="text-xs text-slate-400">Security Platform</div></div>
        </div>
        <nav className="flex-1 p-3 space-y-1">
          {nav.map(n => {
            const active = pathname === n.to || (n.to !== '/' && pathname.startsWith(n.to))
            return <Link key={n.to} to={n.to} className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm ${active ? 'bg-indigo-600 text-white' : 'hover:bg-slate-800 text-slate-300'}`}><n.icon size={18} /> {n.label}</Link>
          })}
        </nav>
        <div className="p-4 border-t border-slate-800">
          <div className="text-sm text-white font-medium">{user?.fullName}</div>
          <div className="text-xs text-slate-400">{user?.email} • {user?.role}</div>
          <button onClick={() => { logout(); nav2('/login') }} className="mt-3 flex items-center gap-2 text-xs text-slate-400 hover:text-white"><LogOut size={14} /> Logout</button>
        </div>
      </aside>
      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-14 bg-white border-b flex items-center justify-between px-4 md:px-6 sticky top-0 z-20">
          <button onClick={() => setOpen(!open)} className="md:hidden p-2"><Menu size={20} /></button>
          <div className="hidden md:flex items-center gap-2 text-sm text-slate-500"><Search size={16} /> <span>Single Source of Truth for Technical Security Risk</span></div>
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 text-xs bg-emerald-50 text-emerald-700 px-3 py-1 rounded-full border border-emerald-200">● SaaS • Hybrid • On-Prem</div>
          </div>
        </header>
        <main className="flex-1 p-4 md:p-6">{children}</main>
      </div>
    </div>
  )
}
