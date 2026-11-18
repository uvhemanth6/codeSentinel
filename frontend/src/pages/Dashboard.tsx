import { ArrowRight, FolderOpen, Plus, ShieldAlert } from 'lucide-react'
import { Link } from 'react-router-dom'
import { CategoryBars, LanguageBars, SeverityPie } from '../components/Charts'
import { EmptyState, ErrorBox, PageHeader, ScoreRing, Spinner, StatCard } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { SEV_COLOR, scoreColor, timeAgo } from '../utils/format'

export default function Dashboard() {
  const { data, error, loading, reload } = useAsync(() => api.dashboard(), [])
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading || !data) return <Spinner label="Loading dashboard…" />
  const d = data.latest

  if (!d) {
    return (
      <>
        <PageHeader title="Dashboard" subtitle="Real results from your scans appear here." />
        <EmptyState icon={<ShieldAlert />} title="No scans yet"
          action={<div className="flex flex-wrap justify-center gap-3"><Link to="/scan/new" className="btn-primary"><Plus className="h-4 w-4" />Run your first scan</Link></div>}>
          Nothing is shown until you scan something — CodeSentinel never displays placeholder metrics as real results. Upload a ZIP, paste a public GitHub URL, or scan a bundled sample project.
        </EmptyState>
      </>
    )
  }
  const s = d.scores
  const dims = s.dimensions
  return (
    <div className="space-y-6">
      <PageHeader title="Dashboard" subtitle={<>Latest scan: <Link className="text-accent-300 hover:underline" to={`/scans/${d.scan_id}`}>{d.name}</Link> · {timeAgo(d.created_at)} · {data.completed_scans} completed scan{data.completed_scans === 1 ? '' : 's'} stored</>}
        actions={<><Link to="/scan/new" className="btn-primary"><Plus className="h-4 w-4" />New scan</Link><Link to={`/scans/${d.scan_id}`} className="btn-secondary">Open results<ArrowRight className="h-4 w-4" /></Link></>} />

      <section className="card-pad flex flex-wrap items-center justify-around gap-8">
        <ScoreRing score={s.overall} size={160} label="Repository health" sub={`grade ${s.grade}`} />
        <ScoreRing score={dims.security.score} size={110} label="Security" />
        <ScoreRing score={dims.quality.score} size={110} label="Code quality" />
        <ScoreRing score={dims.completeness.score} size={110} label="Completeness" />
        <ScoreRing score={dims.maintainability.score} size={110} label="Maintainability" />
        <ScoreRing score={s.slop.score} size={110} label="Code slop" invert sub="↓ better" />
      </section>

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total findings" value={s.counts.total} />
        <StatCard label="Critical" value={s.counts.critical} color={s.counts.critical ? SEV_COLOR.critical : '#34d399'} />
        <StatCard label="High" value={s.counts.high} color={s.counts.high ? SEV_COLOR.high : '#34d399'} />
        <StatCard label="Medium / Low" value={`${s.counts.medium} / ${s.counts.low}`} color={scoreColor(80)} sub={`${d.files_scanned} files · ${d.code_lines.toLocaleString()} code lines`} />
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        <div className="card-pad"><h3 className="mb-4 font-semibold text-white">Severity distribution</h3><SeverityPie counts={s.counts} /></div>
        <div className="card-pad"><h3 className="mb-4 font-semibold text-white">Findings by category</h3><CategoryBars counts={d.by_category} /></div>
        <div className="card-pad"><h3 className="mb-4 font-semibold text-white">Language distribution</h3><LanguageBars languages={d.languages} /></div>
      </section>

      <section className="card overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4"><h3 className="font-semibold text-white">Recent scans</h3><Link to="/history" className="text-sm text-accent-300 hover:underline">View all</Link></div>
        <RecentTable scans={data.recent} />
      </section>
    </div>
  )
}

export function RecentTable({ scans }: { scans: Awaited<ReturnType<typeof api.listScans>> }) {
  if (!scans.length) return <p className="px-5 pb-6 text-sm text-slate-400"><FolderOpen className="mr-2 inline h-4 w-4" />No scans.</p>
  return (
    <table className="w-full text-sm">
      <thead className="bg-ink-850/80 text-left text-xs uppercase tracking-wider text-slate-400"><tr><th className="px-5 py-2.5">Scan</th><th className="px-3 py-2.5">Status</th><th className="px-3 py-2.5">Health</th><th className="hidden px-3 py-2.5 sm:table-cell">Findings</th><th className="px-5 py-2.5 text-right">When</th></tr></thead>
      <tbody>
        {scans.map((sc) => (
          <tr key={sc.id} className="border-t border-ink-600/40 hover:bg-ink-700/30">
            <td className="px-5 py-3"><Link to={`/scans/${sc.id}`} className="font-medium text-white hover:text-accent-300">{sc.name}</Link><p className="text-xs text-slate-500">{sc.source_type}</p></td>
            <td className="px-3 py-3"><StatusChip status={sc.status} /></td>
            <td className="px-3 py-3 font-bold" style={{ color: scoreColor(sc.summary?.scores.overall) }}>{sc.summary?.scores.overall ?? '—'}</td>
            <td className="hidden px-3 py-3 text-slate-300 sm:table-cell">{sc.summary?.scores.counts.total ?? '—'}</td>
            <td className="px-5 py-3 text-right text-slate-400">{timeAgo(sc.created_at)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function StatusChip({ status }: { status: string }) {
  const m: Record<string, string> = { completed: 'border-emerald-400/40 text-emerald-300', failed: 'border-sev-critical/40 text-sev-critical', running: 'border-accent-400/40 text-accent-300', queued: 'border-slate-400/30 text-slate-300' }
  return <span className={`chip capitalize ${m[status] ?? ''}`}>{status}</span>
}
