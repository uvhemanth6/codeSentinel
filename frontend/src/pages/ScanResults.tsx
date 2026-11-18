import { Download, FileText, Github, Package, RefreshCw, Upload } from 'lucide-react'
import { useEffect, useRef } from 'react'
import { Link, NavLink, Outlet, useOutletContext, useParams } from 'react-router-dom'
import StageTracker from '../components/StageTracker'
import { EmptyState, ErrorBox, Spinner } from '../components/ui'
import { useScan } from '../hooks/useScan'
import { api } from '../services/api'
import type { Scan } from '../types'
import { fmtDate } from '../utils/format'

export interface ScanCtx { scan: Scan; reload: () => void; setScan: (s: Scan) => void }
export const useScanCtx = () => useOutletContext<ScanCtx>()

const TABS = [
  { to: '', label: 'Overview', end: true },
  { to: 'security', label: 'Security' },
  { to: 'slop', label: 'Code Slop' },
  { to: 'gaps', label: 'Coding Gaps' },
  { to: 'ai', label: 'AI Review' },
  { to: 'files', label: 'Files' },
]

export default function ScanResults() {
  const { id } = useParams()
  const { scan, error, reload, setScan } = useScan(id)
  const autoAi = useRef(false)

  // Optional AI review requested (with explicit consent) at scan time.
  useEffect(() => {
    if (scan?.status === 'completed' && scan.options?.ai_consent && scan.result && !scan.result.ai.gemini
      && !scan.result.ai.last_attempt && !autoAi.current) {
      autoAi.current = true
      api.aiReview(scan.id, 10).finally(reload)
    }
  }, [scan, reload])

  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (!scan) return <Spinner label="Loading scan…" />

  const SourceIcon = scan.source_type === 'github' ? Github : scan.source_type === 'zip' ? Upload : Package

  if (scan.status === 'queued' || scan.status === 'running') {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="h-page">Scanning {scan.name}…</h1>
          <p className="mt-1 text-sm text-slate-400">Each stage below is reported by the real pipeline as it executes. Source is never executed.</p>
        </div>
        <StageTracker stages={scan.stages} />
      </div>
    )
  }
  if (scan.status === 'failed') {
    return (
      <div className="space-y-6">
        <EmptyState icon={<RefreshCw />} title="Scan failed" action={<Link className="btn-primary" to="/scan/new">Start a new scan</Link>}>
          <p className="text-sev-critical">{scan.error}</p>
        </EmptyState>
        <StageTracker stages={scan.stages} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="h-page">{scan.name}</h1>
          <p className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-slate-400">
            <span className="inline-flex items-center gap-1.5"><SourceIcon className="h-4 w-4" />{scan.source_type === 'github' ? scan.source_ref : scan.source_type === 'sample' ? 'bundled sample' : 'ZIP upload'}</span>
            <span>{fmtDate(scan.finished_at)}</span>
            <span className="font-mono text-xs">{scan.id}</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {(['md', 'json', 'html'] as const).map((f) => (
            <a key={f} className="btn-secondary" href={api.reportUrl(scan.id, f)} download>
              {f === 'md' ? <FileText className="h-4 w-4" /> : <Download className="h-4 w-4" />}{f.toUpperCase()}
            </a>
          ))}
        </div>
      </div>
      <nav className="flex gap-1 overflow-x-auto rounded-2xl border border-ink-600/60 bg-ink-800/60 p-1.5" aria-label="Scan sections">
        {TABS.map((t) => (
          <NavLink key={t.label} to={t.to} end={t.end}
            className={({ isActive }) => `whitespace-nowrap rounded-xl px-4 py-2 text-sm font-semibold transition ${isActive ? 'bg-gradient-to-r from-brand-600 to-brand-500 text-white shadow-glow' : 'text-slate-400 hover:text-white'}`}>
            {t.label}
          </NavLink>
        ))}
      </nav>
      <Outlet context={{ scan, reload, setScan } satisfies ScanCtx} />
    </div>
  )
}
