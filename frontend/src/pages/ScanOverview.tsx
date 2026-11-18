import { AlertOctagon, CheckCircle2, FileSearch, Info, MinusCircle, ShieldAlert, XCircle } from 'lucide-react'
import { Link } from 'react-router-dom'
import { CategoryBars, LanguageBars, SeverityPie } from '../components/Charts'
import { Collapsible, Notice, ScoreRing, StatCard } from '../components/ui'
import { SEV_COLOR, scoreColor } from '../utils/format'
import { useScanCtx } from './ScanResults'

export default function ScanOverview() {
  const { scan } = useScanCtx()
  const r = scan.result!
  const s = r.summary.scores
  const c = s.counts
  const cats = { Security: 0, 'Code Slop': 0, 'Coding Gaps': 0, 'Loose Ends': 0 } as Record<string, number>
  const det = r.ai.deterministic

  if (r.summary.files_scanned === 0) {
    return <Notice tone="warn">No analysable source files were found in this input, so no scores were produced. {Object.entries(r.skipped.counts).map(([k, v]) => `${v} ${k}`).join(', ') && `Excluded: ${Object.entries(r.skipped.counts).map(([k, v]) => `${v} ${k}`).join(', ')}.`}</Notice>
  }
  // category counts are returned via dimension findings; use dashboard-like grouping from dimensions
  const dims = s.dimensions
  return (
    <div className="space-y-6">
      <section className="card-pad grid gap-8 lg:grid-cols-[auto_1fr]">
        <div className="flex flex-wrap items-center justify-center gap-6">
          <ScoreRing score={s.overall} size={168} label="Repository health" sub={`grade ${s.grade}`} />
          <div className="grid grid-cols-2 gap-5">
            {(Object.keys(dims) as (keyof typeof dims)[]).map((k) => <ScoreRing key={k} score={dims[k].score} size={92} label={dims[k].label} />)}
          </div>
        </div>
        <div className="space-y-4">
          <div>
            <p className="label">Executive summary</p>
            <p className="mt-1 text-sm leading-relaxed text-slate-300">{det.executive_summary}</p>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            {r.structure.frameworks.map((f) => <span key={f} className="chip border-brand-400/40 bg-brand-500/10 text-brand-300">{f}</span>)}
            {r.summary.scores.counts.total === 0 && <span className="chip border-emerald-400/40 text-emerald-300">No findings</span>}
          </div>
          <Notice tone="info"><Info className="mr-1.5 inline h-4 w-4" />{s.method}</Notice>
        </div>
      </section>

      <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard label="Total findings" value={c.total} sub={`${r.summary.duplicates_merged} duplicate detections merged`} icon={<ShieldAlert className="h-4 w-4" />} />
        <StatCard label="Critical / High" value={`${c.critical} / ${c.high}`} color={c.critical + c.high ? SEV_COLOR.high : '#34d399'} sub="Fix these first" icon={<AlertOctagon className="h-4 w-4" />} />
        <StatCard label="Code slop score" value={s.slop.score ?? '—'} color={scoreColor(s.slop.score, true)} sub="0–100 · higher is worse" />
        <StatCard label="Files analysed" value={r.summary.files_scanned} sub={`${r.summary.code_lines.toLocaleString()} code lines · ${r.summary.files_skipped} excluded`} icon={<FileSearch className="h-4 w-4" />} />
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="card-pad"><h3 className="mb-4 font-semibold text-white">Severity distribution</h3><SeverityPie counts={c} /></div>
        <div className="card-pad"><h3 className="mb-4 font-semibold text-white">Language distribution <span className="text-xs font-normal text-slate-500">(lines · purple = full support, cyan = partial)</span></h3><LanguageBars languages={r.languages.languages} /></div>
      </section>

      <section className="card-pad">
        <h3 className="mb-1 font-semibold text-white">How each score is calculated</h3>
        <p className="mb-4 text-sm text-slate-400">Every finding counts toward exactly one dimension, so nothing is double counted. Weights are configurable in Settings.</p>
        <div className="space-y-2">
          {(Object.keys(dims) as (keyof typeof dims)[]).map((k) => (
            <Collapsible key={k} title={<span className="flex items-center gap-3">{dims[k].label}<b style={{ color: scoreColor(dims[k].score) }}>{dims[k].score ?? '—'}/100</b><span className="text-xs font-normal text-slate-500">weight {Math.round((s.weights[k] ?? 0) * 100)}%</span></span>}>
              <p>{dims[k].explanation}</p>
            </Collapsible>
          ))}
          <Collapsible title={<span className="flex items-center gap-3">Code slop score <b style={{ color: scoreColor(s.slop.score, true) }}>{s.slop.score ?? '—'}/100</b><span className="text-xs font-normal text-slate-500">higher = more concerns</span></span>}><p>{s.slop.explanation}</p></Collapsible>
        </div>
      </section>

      {det.architectural_risks.length > 0 && (
        <section className="card-pad">
          <h3 className="mb-3 font-semibold text-white">Architectural observations <span className="text-xs font-normal text-slate-500">derived from scanner facts</span></h3>
          <ul className="grid gap-3 md:grid-cols-2">
            {det.architectural_risks.map((a) => (
              <li key={a.title} className="rounded-xl border border-ink-600/60 bg-ink-850/60 p-4">
                <p className="font-semibold text-white">{a.title}</p>
                <p className="mt-1 text-sm text-slate-400">{a.description}</p>
                <p className="mt-2 text-xs text-accent-300">Evidence: {a.evidence}</p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="grid gap-4 lg:grid-cols-2">
        <div className="card-pad">
          <h3 className="mb-3 font-semibold text-white">Analysis tools</h3>
          <ul className="space-y-2 text-sm">
            {r.analyzers.map((a) => (
              <li key={a.name} className="flex items-center justify-between gap-3">
                <span className="flex items-center gap-2 text-slate-300">
                  {a.status === 'ran' ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : a.status === 'failed' ? <XCircle className="h-4 w-4 text-sev-critical" /> : <MinusCircle className="h-4 w-4 text-slate-500" />}
                  {a.name}
                </span>
                <span className="truncate text-xs text-slate-500" title={a.error ?? ''}>{a.status === 'ran' ? `${a.findings} raw findings${a.error ? ' (partial)' : ''}` : a.error ?? a.status}</span>
              </li>
            ))}
          </ul>
          {Object.entries(r.tools).filter(([, t]) => t.status !== 'ran').map(([k, t]) => (
            <p key={k} className="mt-2 text-xs text-slate-500"><b className="text-slate-400">{k}</b>: {t.status}{t.reason ? ` — ${t.reason}` : ''}</p>
          ))}
        </div>
        <div className="card-pad">
          <h3 className="mb-3 font-semibold text-white">Project structure</h3>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <dt className="text-slate-400">Tests detected</dt><dd className={r.structure.has_tests ? 'text-emerald-300' : 'text-amber-300'}>{r.structure.has_tests ? 'Yes' : 'No'}</dd>
            <dt className="text-slate-400">README</dt><dd className={r.structure.has_readme ? 'text-emerald-300' : 'text-amber-300'}>{r.structure.has_readme ? 'Yes' : 'No'}</dd>
            <dt className="text-slate-400">Max depth</dt><dd>{r.structure.max_depth}</dd>
            <dt className="text-slate-400">Manifests</dt><dd className="truncate" title={r.structure.manifests.join(', ')}>{r.structure.manifests.length || '—'}</dd>
          </dl>
          {r.structure.entry_points.length > 0 && <p className="mt-3 text-xs text-slate-400">Entry points: <span className="font-mono text-slate-300">{r.structure.entry_points.slice(0, 4).join(', ')}</span></p>}
          {r.languages.unsupported.length > 0 && <p className="mt-3 text-xs text-amber-300/90">Unsupported file types (not analysed): {r.languages.unsupported.slice(0, 6).map((u) => `${u.extension} ×${u.files}`).join(', ')}</p>}
          {r.summary.files_skipped > 0 && <p className="mt-2 text-xs text-slate-500">Excluded: {Object.entries(r.skipped.counts).map(([k, v]) => `${v} ${k}`).join(', ')}</p>}
        </div>
      </section>

      <div className="flex flex-wrap gap-3">
        <Link className="btn-primary" to="security"><ShieldAlert className="h-4 w-4" />Review security findings</Link>
        <Link className="btn-secondary" to="ai">AI &amp; remediation plan</Link>
        <Link className="btn-secondary" to="files">Browse files</Link>
      </div>
    </div>
  )
}
