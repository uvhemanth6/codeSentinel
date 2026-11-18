import { Bot, Eye, Layers, Lightbulb, ListChecks, Loader2, Send, ShieldCheck, Sparkles } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { Notice, SeverityBadge } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import type { AiPreview, GeminiReview } from '../types'
import { FALLBACK_REASONS } from '../utils/format'
import { useScanCtx } from './ScanResults'

export default function AIReview() {
  const { scan, reload } = useScanCtx()
  const result = scan.result!
  const det = result.ai.deterministic
  const gem = result.ai.gemini
  const last = result.ai.last_attempt
  const { data: health } = useAsync(() => api.health(), [])
  const [consent, setConsent] = useState(false)
  const [limit, setLimit] = useState(10)
  const [preview, setPreview] = useState<AiPreview | null>(null)
  const [busy, setBusy] = useState<'preview' | 'run' | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [outcome, setOutcome] = useState<GeminiReview | null>(null)

  const configured = health?.tools.gemini.configured ?? false
  const doPreview = async () => {
    setBusy('preview'); setErr(null)
    try { setPreview(await api.aiPreview(scan.id, limit)) } catch (e) { setErr((e as Error).message) } finally { setBusy(null) }
  }
  const run = async () => {
    setBusy('run'); setErr(null)
    try { setOutcome(await api.aiReview(scan.id, limit)); reload() } catch (e) { setErr((e as Error).message) } finally { setBusy(null) }
  }
  const fb = outcome && outcome.mode !== 'gemini' ? outcome : last && !gem && last.mode !== 'gemini' ? { fallback_reason: last.fallback_reason, message: last.message ?? '' } : null

  return (
    <div className="space-y-6">
      {/* ---------------- deterministic */}
      <section className="card-pad space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-lg font-bold text-white"><ShieldCheck className="h-5 w-5 text-emerald-400" />Deterministic analysis</h2>
          <span className="chip border-emerald-400/40 bg-emerald-400/10 text-emerald-300">Derived from scanner results · no external AI</span>
        </div>
        <p className="text-sm leading-relaxed text-slate-300">{det.executive_summary}</p>

        <div>
          <h3 className="mb-3 flex items-center gap-2 font-semibold text-white"><ListChecks className="h-4 w-4 text-accent-400" />Prioritised remediation plan</h3>
          {det.remediation_plan.length === 0 ? <p className="text-sm text-slate-400">Nothing to remediate.</p> : (
            <ol className="space-y-2">
              {det.remediation_plan.slice(0, 10).map((p) => (
                <li key={p.family} className="flex gap-3 rounded-xl border border-ink-600/60 bg-ink-850/60 p-3">
                  <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-brand-500/20 text-sm font-bold text-brand-300">{p.order}</span>
                  <div className="min-w-0 flex-1">
                    <p className="flex flex-wrap items-center gap-2 font-medium text-white"><SeverityBadge severity={p.severity} />{p.title}</p>
                    <p className="mt-1 text-sm text-slate-400">{p.action}</p>
                    <p className="mt-1 text-xs text-slate-500">{p.count} finding{p.count > 1 ? 's' : ''} · effort: {p.effort} · {p.category}</p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>

        {det.related_issue_groups.length > 0 && (
          <div>
            <h3 className="mb-3 flex items-center gap-2 font-semibold text-white"><Layers className="h-4 w-4 text-accent-400" />Related issue groups</h3>
            <div className="grid gap-3 md:grid-cols-2">
              {det.related_issue_groups.map((g) => <div key={g.label} className="rounded-xl border border-ink-600/60 bg-ink-850/60 p-3 text-sm"><p className="font-semibold text-white">{g.label}</p><p className="text-slate-400">{g.reason}</p></div>)}
            </div>
          </div>
        )}
        {det.architectural_risks.length > 0 && (
          <div>
            <h3 className="mb-3 font-semibold text-white">Architectural risks</h3>
            <ul className="space-y-2">{det.architectural_risks.map((a) => <li key={a.title} className="text-sm"><b className="text-white">{a.title}</b> — <span className="text-slate-400">{a.description}</span> <span className="text-xs text-accent-300">({a.evidence})</span></li>)}</ul>
          </div>
        )}
      </section>

      {/* ---------------- gemini */}
      <section className="card-pad space-y-4 border-brand-500/30">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="flex items-center gap-2 text-lg font-bold text-white"><Sparkles className="h-5 w-5 text-brand-400" />Gemini deep review <span className="text-xs font-normal text-slate-500">optional</span></h2>
          <span className={`chip ${configured ? 'border-emerald-400/40 text-emerald-300' : 'border-amber-400/40 text-amber-300'}`}>{configured ? `API key configured · ${health?.tools.gemini.model}` : 'No GEMINI_API_KEY configured'}</span>
        </div>

        {!configured && <Notice tone="warn">AI analysis is disabled because no <code className="font-mono">GEMINI_API_KEY</code> is set on the backend. Everything above works without it. See <Link to="/settings" className="underline">Settings</Link> for setup.</Notice>}

        <Notice tone="ai">
          <b>Data disclosure.</b> If you run this review, only a limited set of finding snippets (a few lines of code each, never the whole repository) are sent to Google's Gemini API. Secrets are masked before sending. Use “Preview data” to see exactly what would be transmitted. AI output is shown as <b>unverified hypotheses</b>; file paths and line numbers always come from the scanner.
        </Notice>

        <div className="flex flex-wrap items-end gap-4">
          <label className="text-sm text-slate-300">Findings to send
            <select className="input mt-1 w-28" value={limit} onChange={(e) => setLimit(Number(e.target.value))}>{[5, 10, 15].map((n) => <option key={n} value={n}>{n}</option>)}</select>
          </label>
          <button className="btn-secondary" onClick={doPreview} disabled={busy !== null}>{busy === 'preview' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Eye className="h-4 w-4" />}Preview data</button>
          <label className="flex max-w-md items-start gap-2 text-sm text-slate-300">
            <input type="checkbox" className="mt-1 h-4 w-4 accent-brand-500" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            I understand redacted snippets of the selected findings will be sent to Google Gemini.
          </label>
          <button className="btn-primary" disabled={!consent || busy !== null || !configured} onClick={run}>{busy === 'run' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Send className="h-4 w-4" />}Run Gemini review</button>
        </div>
        {err && <p className="text-sm text-sev-critical">{err}</p>}

        {preview && (
          <div className="rounded-xl border border-ink-600/60 bg-ink-950 p-4">
            <p className="mb-2 text-sm font-semibold text-white">This is exactly what would be sent ({preview.payload.findings.length} findings)</p>
            <p className="mb-3 text-xs text-slate-400">{preview.disclosure}</p>
            <pre className="max-h-72 overflow-auto font-mono text-xs text-slate-300">{JSON.stringify(preview.payload, null, 2)}</pre>
          </div>
        )}

        {fb && (
          <Notice tone="warn"><b>AI unavailable — deterministic analysis shown instead.</b> {fb.fallback_reason ? FALLBACK_REASONS[fb.fallback_reason] ?? fb.fallback_reason : ''}{fb.message ? ` — ${fb.message}` : ''}</Notice>
        )}

        {gem?.mode === 'gemini' && gem.review && (
          <div className="space-y-5 rounded-xl border border-brand-400/30 bg-brand-500/5 p-5">
            <div className="flex flex-wrap items-center gap-2"><Bot className="h-5 w-5 text-brand-400" /><b className="text-white">AI-generated hypotheses</b><span className="chip border-brand-400/40 text-brand-300">{gem.model}</span><span className="chip border-amber-400/40 text-amber-300">Not verified</span><span className="text-xs text-slate-500">{gem.sent_findings} findings sent</span></div>
            <p className="text-xs text-slate-400">{gem.disclaimer}</p>
            <p className="text-sm leading-relaxed text-slate-200">{gem.review.executive_summary}</p>
            {gem.review.architectural_risks.length > 0 && <div><h4 className="mb-2 font-semibold text-white">Architectural risks (AI)</h4><ul className="space-y-2 text-sm">{gem.review.architectural_risks.map((a, i) => <li key={i}><b className="text-white">{a.title}</b> — <span className="text-slate-300">{a.description}</span></li>)}</ul></div>}
            {gem.review.prioritized_remediation.length > 0 && <div><h4 className="mb-2 font-semibold text-white">Suggested priority</h4><ol className="space-y-1.5 text-sm">{gem.review.prioritized_remediation.map((p) => <li key={p.finding_id} className="flex flex-wrap items-center gap-2"><span className="font-bold text-brand-300">#{p.priority}</span><SeverityBadge severity={p.severity} /><span className="text-white">{p.title}</span><span className="font-mono text-xs text-accent-300">{p.file}{p.line ? `:${p.line}` : ''}</span><span className="text-slate-400">— {p.rationale}</span></li>)}</ol></div>}
            {gem.review.finding_reviews.length > 0 && (
              <div><h4 className="mb-2 flex items-center gap-2 font-semibold text-white"><Lightbulb className="h-4 w-4 text-amber-300" />Per-finding analysis</h4>
                <div className="space-y-3">{gem.review.finding_reviews.map((r) => (
                  <div key={r.finding_id} className="rounded-xl border border-ink-600/60 bg-ink-900/60 p-4 text-sm">
                    <p className="flex flex-wrap items-center gap-2"><SeverityBadge severity={r.severity} /><b className="text-white">{r.title}</b><span className="font-mono text-xs text-accent-300">{r.file}{r.line ? `:${r.line}` : ''}</span></p>
                    <p className="mt-2 text-slate-300">{r.technical_implication}</p>
                    {r.likely_false_positive && <p className="mt-2 text-amber-300">Possible false positive: {r.false_positive_reason}</p>}
                    {r.suggested_fix_code && <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-xs text-slate-200">{r.suggested_fix_code}</pre>}
                  </div>))}
                </div>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
