import { Activity, Bot, Bug, FileWarning, History, LayoutDashboard, Menu, PlusCircle, Settings as Cog, ShieldAlert, Sparkles, X } from 'lucide-react'
import { ReactNode, useState } from 'react'
import { NavLink, Outlet, useMatch } from 'react-router-dom'
import Logo from '../components/Logo'
import { useLatestScanId } from '../hooks/useLatestScan'

interface Item { to: string; label: string; icon: ReactNode; needsScan?: boolean; end?: boolean }

export default function AppLayout() {
  const [open, setOpen] = useState(false)
  const latest = useLatestScanId()
  const match = useMatch('/scans/:id/*')
  const sid = match?.params.id ?? latest
  const items: Item[] = [
    { to: '/dashboard', label: 'Dashboard', icon: <LayoutDashboard className="h-4 w-4" /> },
    { to: '/scan/new', label: 'New Scan', icon: <PlusCircle className="h-4 w-4" /> },
    { to: `/scans/${sid}`, label: 'Scan Results', icon: <Activity className="h-4 w-4" />, needsScan: true, end: true },
    { to: `/scans/${sid}/security`, label: 'Security Findings', icon: <ShieldAlert className="h-4 w-4" />, needsScan: true },
    { to: `/scans/${sid}/slop`, label: 'Code Slop', icon: <Bug className="h-4 w-4" />, needsScan: true },
    { to: `/scans/${sid}/gaps`, label: 'Coding Gaps', icon: <FileWarning className="h-4 w-4" />, needsScan: true },
    { to: `/scans/${sid}/ai`, label: 'AI Review', icon: <Sparkles className="h-4 w-4" />, needsScan: true },
    { to: '/history', label: 'Scan History', icon: <History className="h-4 w-4" /> },
    { to: '/settings', label: 'Settings', icon: <Cog className="h-4 w-4" /> },
  ]

  const nav = (
    <nav className="flex flex-col gap-1" aria-label="Main">
      {items.map((it) =>
        it.needsScan && !sid ? (
          <span key={it.label} title="Run a scan first" className="flex cursor-not-allowed items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium text-slate-600">{it.icon}{it.label}</span>
        ) : (
          <NavLink key={it.label} to={it.to} end={it.end} onClick={() => setOpen(false)}
            className={({ isActive }) => `flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition ${isActive ? 'bg-gradient-to-r from-brand-600/30 to-accent-500/10 text-white ring-1 ring-brand-500/40' : 'text-slate-400 hover:bg-ink-700/60 hover:text-white'}`}>
            {it.icon}{it.label}
          </NavLink>
        ),
      )}
    </nav>
  )

  return (
    <div className="min-h-screen lg:flex">
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-ink-600/50 bg-ink-900/80 p-5 backdrop-blur lg:flex">
        <Logo to="/dashboard" />
        <div className="mt-8 flex-1 overflow-y-auto">{nav}</div>
        <p className="mt-6 rounded-xl border border-ink-600/60 bg-ink-800/60 p-3 text-[11px] leading-relaxed text-slate-400">
          <Bot className="mb-1 h-4 w-4 text-brand-400" />
          Scores are heuristic indicators, not a security certification.
        </p>
      </aside>
      <div className="flex-1">
        <header className="sticky top-0 z-30 flex items-center justify-between border-b border-ink-600/50 bg-ink-900/85 px-4 py-3 backdrop-blur lg:hidden">
          <Logo to="/dashboard" />
          <button className="btn-ghost p-2" onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
        </header>
        {open && (
          <div className="fixed inset-0 z-40 lg:hidden">
            <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
            <div className="absolute left-0 top-0 h-full w-72 bg-ink-900 p-5 shadow-2xl">
              <div className="mb-6 flex items-center justify-between"><Logo to="/dashboard" /><button className="btn-ghost p-2" onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-5 w-5" /></button></div>
              {nav}
            </div>
          </div>
        )}
        <main className="mx-auto w-full max-w-7xl px-4 py-8 sm:px-8"><Outlet /></main>
      </div>
    </div>
  )
}
