import { ChevronRight, Search } from 'lucide-react'
import { Fragment, useMemo, useState } from 'react'
import FindingsExplorer from '../components/FindingsExplorer'
import { ErrorBox, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { fmtBytes } from '../utils/format'
import { useScanCtx } from './ScanResults'

export default function FilesTab() {
  const { scan } = useScanCtx()
  const { data, error, loading, reload } = useAsync(() => api.files(scan.id), [scan.id])
  const [q, setQ] = useState('')
  const [sort, setSort] = useState<'findings' | 'path' | 'lines'>('findings')
  const [open, setOpen] = useState<string | null>(null)

  const rows = useMemo(() => {
    const list = (data?.files ?? []).filter((f) => f.path.toLowerCase().includes(q.toLowerCase()))
    return list.sort((a, b) => sort === 'path' ? a.path.localeCompare(b.path) : sort === 'lines' ? b.lines - a.lines : b.findings - a.findings)
  }, [data, q, sort])

  if (error) return <ErrorBox message={error} onRetry={reload} />
  if (loading || !data) return <Spinner label="Loading files…" />
  return (
    <div className="space-y-4">
      <div className="card-pad flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" /><input className="input pl-9" placeholder="Filter files…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter files" /></div>
        <select className="input w-auto" value={sort} onChange={(e) => setSort(e.target.value as any)} aria-label="Sort files">
          <option value="findings">Most findings</option><option value="lines">Largest</option><option value="path">Path</option>
        </select>
        <span className="text-sm text-slate-400">{rows.length} files</span>
      </div>
      <div className="card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-ink-850/80 text-left text-xs uppercase tracking-wider text-slate-400">
            <tr><th className="px-4 py-3">File</th><th className="px-4 py-3">Language</th><th className="hidden px-4 py-3 sm:table-cell">Lines</th><th className="hidden px-4 py-3 md:table-cell">Size</th><th className="px-4 py-3 text-right">Findings</th></tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <Fragment key={f.path}>
                <tr className={`cursor-pointer border-t border-ink-600/40 transition hover:bg-ink-700/30 ${open === f.path ? 'bg-ink-700/30' : ''}`} onClick={() => f.findings && setOpen(open === f.path ? null : f.path)}>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-200"><span className="inline-flex items-center gap-1.5"><ChevronRight className={`h-3.5 w-3.5 transition ${open === f.path ? 'rotate-90' : ''} ${f.findings ? 'text-accent-400' : 'text-slate-700'}`} />{f.path}</span></td>
                  <td className="px-4 py-2.5"><span className={`chip ${f.support === 'full' ? 'border-brand-400/40 text-brand-300' : f.support === 'partial' ? 'border-accent-400/40 text-accent-300' : 'border-amber-400/40 text-amber-300'}`}>{f.language}{f.support !== 'full' ? ` · ${f.support}` : ''}</span></td>
                  <td className="hidden px-4 py-2.5 text-slate-400 sm:table-cell">{f.lines}</td>
                  <td className="hidden px-4 py-2.5 text-slate-400 md:table-cell">{fmtBytes(f.bytes)}</td>
                  <td className="px-4 py-2.5 text-right font-semibold">{f.findings ? <span className="text-white">{f.findings}</span> : <span className="text-slate-600">0</span>}</td>
                </tr>
                {open === f.path && (
                  <tr className="border-t border-ink-600/40 bg-ink-900/40"><td colSpan={5} className="p-4"><FindingsExplorer scanId={scan.id} categories={[]} file={f.path} emptyMessage="No findings in this file." aiReview={scan.result?.ai.gemini} /></td></tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="p-8 text-center text-sm text-slate-400">No files match.</p>}
      </div>
    </div>
  )
}
