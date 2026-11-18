import { Download, ExternalLink, Search, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { EmptyState, ErrorBox, PageHeader, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { fmtDate, scoreColor } from '../utils/format'
import { StatusChip } from './Dashboard'

export default function History() {
  const { data, error, loading, reload } = useAsync(() => api.listScans(), [])
  const [q, setQ] = useState('')
  const [status, setStatus] = useState('')
  const [sort, setSort] = useState<'date' | 'health' | 'findings'>('date')
  const [confirm, setConfirm] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  const rows = useMemo(() => {
    const l = (data ?? []).filter((s) => (!status || s.status === status) && (s.name + s.source_ref).toLowerCase().includes(q.toLowerCase()))
    return l.sort((a, b) => sort === 'health' ? (b.summary?.scores.overall ?? -1) - (a.summary?.scores.overall ?? -1)
      : sort === 'findings' ? (b.summary?.scores.counts.total ?? -1) - (a.summary?.scores.counts.total ?? -1) : b.created_at - a.created_at)
  }, [data, q, status, sort])

  const del = async (id: string) => {
    try { await api.deleteScan(id); setConfirm(null); reload() } catch (e) { setErr((e as Error).message) }
  }
  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading || !data) return <Spinner label="Loading history…" />

  return (
    <div className="space-y-5">
      <PageHeader title="Scan history" subtitle="All scans are stored locally in SQLite. Source code is never retained — only findings and evidence snippets." />
      {data.length === 0 ? (
        <EmptyState title="No scans yet" action={<Link to="/scan/new" className="btn-primary">Start a scan</Link>}>Your completed scans will be listed here.</EmptyState>
      ) : (
        <>
          <div className="card-pad flex flex-wrap items-center gap-3">
            <div className="relative min-w-[220px] flex-1"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" /><input className="input pl-9" placeholder="Search scans…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search scans" /></div>
            <select className="input w-auto" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter status"><option value="">All statuses</option><option value="completed">Completed</option><option value="failed">Failed</option><option value="running">Running</option></select>
            <select className="input w-auto" value={sort} onChange={(e) => setSort(e.target.value as any)} aria-label="Sort scans"><option value="date">Newest</option><option value="health">Health score</option><option value="findings">Most findings</option></select>
          </div>
          {err && <ErrorBox message={err} />}
          <div className="card overflow-x-auto">
            <table className="w-full min-w-[720px] text-sm">
              <thead className="bg-ink-850/80 text-left text-xs uppercase tracking-wider text-slate-400"><tr><th className="px-5 py-3">Scan</th><th className="px-3 py-3">Status</th><th className="px-3 py-3">Health</th><th className="px-3 py-3">Findings</th><th className="px-3 py-3">Date</th><th className="px-5 py-3 text-right">Actions</th></tr></thead>
              <tbody>
                {rows.map((s) => (
                  <tr key={s.id} className="border-t border-ink-600/40 hover:bg-ink-700/30">
                    <td className="px-5 py-3"><Link to={`/scans/${s.id}`} className="font-medium text-white hover:text-accent-300">{s.name}</Link><p className="max-w-[260px] truncate text-xs text-slate-500">{s.source_type} · {s.source_ref}</p>{s.error && <p className="max-w-[260px] truncate text-xs text-sev-critical" title={s.error}>{s.error}</p>}</td>
                    <td className="px-3 py-3"><StatusChip status={s.status} /></td>
                    <td className="px-3 py-3 font-bold" style={{ color: scoreColor(s.summary?.scores.overall) }}>{s.summary?.scores.overall ?? '—'}</td>
                    <td className="px-3 py-3 text-slate-300">{s.summary ? `${s.summary.scores.counts.total} (${s.summary.scores.counts.critical}C/${s.summary.scores.counts.high}H)` : '—'}</td>
                    <td className="px-3 py-3 text-slate-400">{fmtDate(s.created_at)}</td>
                    <td className="px-5 py-3">
                      <div className="flex justify-end gap-1">
                        <Link className="btn-ghost p-2" to={`/scans/${s.id}`} title="Open"><ExternalLink className="h-4 w-4" /></Link>
                        {s.status === 'completed' && <a className="btn-ghost p-2" href={api.reportUrl(s.id, 'html')} download title="Download HTML report"><Download className="h-4 w-4" /></a>}
                        {confirm === s.id ? (
                          <><button className="btn-danger px-2 py-1 text-xs" onClick={() => del(s.id)}>Confirm</button><button className="btn-ghost px-2 py-1 text-xs" onClick={() => setConfirm(null)}>Cancel</button></>
                        ) : <button className="btn-ghost p-2 hover:text-sev-critical" onClick={() => setConfirm(s.id)} title="Delete scan"><Trash2 className="h-4 w-4" /></button>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && <p className="p-8 text-center text-sm text-slate-400">No scans match your filters.</p>}
          </div>
        </>
      )}
    </div>
  )
}
