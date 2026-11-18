import { ArrowDownUp, Search, SearchX } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { api } from '../services/api'
import type { FindingsPage, GeminiReview, Severity } from '../types'
import { SEVERITIES, SEV_COLOR, VERIFY_LABEL } from '../utils/format'
import FindingCard from './FindingCard'
import { EmptyState, ErrorBox, Spinner } from './ui'

const PAGE = 50

export default function FindingsExplorer({ scanId, categories, emptyMessage, file, aiReview }: {
  scanId: string; categories: string[]; emptyMessage: string; file?: string; aiReview?: GeminiReview | null
}) {
  const [q, setQ] = useState('')
  const [dq, setDq] = useState('')
  const [sev, setSev] = useState<Severity[]>([])
  const [sub, setSub] = useState('')
  const [src, setSrc] = useState('')
  const [ver, setVer] = useState('')
  const [reviewed, setReviewed] = useState<'' | 'true' | 'false'>('')
  const [sort, setSort] = useState('priority')
  const [limit, setLimit] = useState(PAGE)
  const [page, setPage] = useState<FindingsPage | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [tick, setTick] = useState(0)

  useEffect(() => { const t = setTimeout(() => setDq(q), 250); return () => clearTimeout(t) }, [q])
  useEffect(() => { setLimit(PAGE) }, [dq, sev, sub, src, ver, reviewed, sort])

  useEffect(() => {
    let alive = true
    setLoading(true)
    api.findings(scanId, {
      category: categories.join(','), severity: sev.join(','), subcategory: sub, source: src, verification: ver,
      reviewed, q: dq, sort, limit, file,
    }).then((p) => { if (alive) { setPage(p); setError(null) } })
      .catch((e) => alive && setError((e as Error).message))
      .finally(() => alive && setLoading(false))
    return () => { alive = false }
  }, [scanId, categories.join(','), sev.join(','), sub, src, ver, reviewed, dq, sort, limit, file, tick])

  const aiNotes = useMemo(() => {
    const m = new Map<string, NonNullable<GeminiReview['review']>['finding_reviews'][number]>()
    aiReview?.review?.finding_reviews.forEach((r) => m.set(r.finding_id, r))
    return m
  }, [aiReview])

  const filtersActive = !!(dq || sev.length || sub || src || ver || reviewed)
  const reset = () => { setQ(''); setSev([]); setSub(''); setSrc(''); setVer(''); setReviewed('') }
  const toggleSev = (s: Severity) => setSev((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]))

  return (
    <div className="space-y-4">
      <div className="card-pad space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[240px] flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input className="input pl-9" placeholder="Search title, file, rule, evidence…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-400">
            <ArrowDownUp className="h-4 w-4" />
            <select className="input w-auto py-2" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort findings">
              <option value="priority">Priority</option>
              <option value="severity">Severity</option>
              <option value="confidence">Confidence</option>
              <option value="file">File</option>
            </select>
          </label>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {SEVERITIES.map((s) => {
            const n = page?.facets.severity[s] ?? 0
            const on = sev.includes(s)
            return (
              <button key={s} onClick={() => toggleSev(s)} disabled={!n && !on} aria-pressed={on}
                className="chip capitalize disabled:opacity-30" style={{ color: SEV_COLOR[s], borderColor: on ? SEV_COLOR[s] : `${SEV_COLOR[s]}44`, background: on ? `${SEV_COLOR[s]}26` : 'transparent' }}>
                {s} <b>{n}</b>
              </button>
            )
          })}
          <select className="input w-auto py-1.5 text-xs" value={sub} onChange={(e) => setSub(e.target.value)} aria-label="Filter by type">
            <option value="">All types</option>
            {Object.entries(page?.facets.subcategory ?? {}).sort().map(([k, v]) => <option key={k} value={k}>{k} ({v})</option>)}
          </select>
          <select className="input w-auto py-1.5 text-xs" value={src} onChange={(e) => setSrc(e.target.value)} aria-label="Filter by detection source">
            <option value="">All sources</option>
            {Object.entries(page?.facets.source ?? {}).sort().map(([k, v]) => <option key={k} value={k}>{k} ({v})</option>)}
          </select>
          <select className="input w-auto py-1.5 text-xs" value={ver} onChange={(e) => setVer(e.target.value)} aria-label="Filter by verification">
            <option value="">All verification</option>
            {Object.entries(page?.facets.verification ?? {}).map(([k, v]) => <option key={k} value={k}>{VERIFY_LABEL[k] ?? k} ({v})</option>)}
          </select>
          <select className="input w-auto py-1.5 text-xs" value={reviewed} onChange={(e) => setReviewed(e.target.value as any)} aria-label="Filter by review status">
            <option value="">Open + reviewed</option>
            <option value="false">Open only</option>
            <option value="true">Reviewed only</option>
          </select>
          {filtersActive && <button className="btn-ghost px-3 py-1.5 text-xs" onClick={reset}>Clear filters</button>}
        </div>
      </div>

      {error && <ErrorBox message={error} onRetry={() => setTick((t) => t + 1)} />}
      {loading && !page && <Spinner label="Loading findings…" />}
      {page && (
        <>
          <div className="flex items-center justify-between text-sm text-slate-400">
            <span>Showing <b className="text-white">{Math.min(page.items.length, page.total)}</b> of <b className="text-white">{page.total}</b> findings{filtersActive && ` (filtered from ${page.base_total})`}</span>
            <span>{page.reviewed_total} reviewed</span>
          </div>
          {page.items.length === 0 ? (
            filtersActive
              ? <EmptyState icon={<SearchX />} title="No findings match these filters" action={<button className="btn-secondary" onClick={reset}>Clear filters</button>} />
              : <EmptyState title="Nothing detected here">{emptyMessage}</EmptyState>
          ) : (
            <div className="space-y-3">
              {page.items.map((f) => (
                <FindingCard key={f.id} scanId={scanId} finding={f} aiNote={aiNotes.get(f.id)} onReviewChange={() => setTick((t) => t + 1)} />
              ))}
            </div>
          )}
          {page.total > page.items.length && (
            <div className="flex justify-center"><button className="btn-secondary" onClick={() => setLimit(limit + PAGE)}>Load more ({page.total - page.items.length} remaining)</button></div>
          )}
        </>
      )}
    </div>
  )
}
