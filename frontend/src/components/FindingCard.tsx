import { Bot, Check, ChevronDown, ClipboardCopy, FileCode2, Wrench } from 'lucide-react'
import { useState } from 'react'
import { api } from '../services/api'
import type { Finding, GeminiReview } from '../types'
import { SEV_COLOR } from '../utils/format'
import { SeverityBadge, VerificationPill } from './ui'

type AiNote = NonNullable<GeminiReview['review']>['finding_reviews'][number]

function CodeEvidence({ f }: { f: Finding }) {
  const lines = f.context.length ? f.context : [{ line: f.line ?? 1, text: f.evidence }]
  return (
    <pre className="overflow-x-auto rounded-xl border border-ink-600/60 bg-ink-950 py-2 font-mono text-[12.5px] leading-6">
      {lines.map((l) => {
        const hit = f.line !== null && l.line >= f.line && l.line <= (f.end_line ?? f.line)
        return (
          <div key={l.line} className={`flex px-3 ${hit ? 'bg-sev-critical/10' : ''}`} style={hit ? { boxShadow: `inset 3px 0 0 ${SEV_COLOR[f.severity]}` } : undefined}>
            <span className="mr-4 w-10 shrink-0 select-none text-right text-slate-600">{l.line}</span>
            <code className={hit ? 'text-slate-100' : 'text-slate-400'}>{l.text || ' '}</code>
          </div>
        )
      })}
    </pre>
  )
}

export function findingToMarkdown(f: Finding): string {
  const loc = f.line ? `${f.file}:${f.line}` : f.file
  return `### [${f.severity.toUpperCase()}] ${f.title}\n- ID: ${f.id} · Rule: ${f.rule_id}\n- Location: ${loc}\n- Verification: ${f.verification} · Confidence: ${f.confidence}\n\n\`\`\`\n${f.evidence}\n\`\`\`\n\n**Why:** ${f.explanation}\n\n**Impact:** ${f.impact}\n\n**Fix:** ${f.remediation}\n`
}

export default function FindingCard({ scanId, finding, aiNote, defaultOpen = false, onReviewChange }: {
  scanId: string; finding: Finding; aiNote?: AiNote; defaultOpen?: boolean; onReviewChange?: (id: string, reviewed: boolean) => void
}) {
  const [open, setOpen] = useState(defaultOpen)
  const [f, setF] = useState(finding)
  const [note, setNote] = useState(finding.review.note)
  const [busy, setBusy] = useState(false)
  const [copied, setCopied] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const save = async (reviewed: boolean, text = note) => {
    setBusy(true); setErr(null)
    try {
      await api.review(scanId, f.id, reviewed, text)
      setF({ ...f, review: { reviewed, note: text } })
      onReviewChange?.(f.id, reviewed)
    } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
  }
  const copy = async () => {
    try { await navigator.clipboard.writeText(findingToMarkdown(f)); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { setErr('Clipboard unavailable') }
  }
  const loc = f.line ? `${f.file}:${f.line}` : f.file

  return (
    <article className={`card overflow-hidden transition ${f.review.reviewed ? 'opacity-60' : ''}`} style={{ borderLeft: `3px solid ${SEV_COLOR[f.severity]}` }}>
      <button className="flex w-full items-start gap-3 px-4 py-3.5 text-left hover:bg-ink-700/30" onClick={() => setOpen(!open)} aria-expanded={open}>
        <div className="mt-0.5"><SeverityBadge severity={f.severity} /></div>
        <div className="min-w-0 flex-1">
          <p className={`font-semibold text-white ${f.review.reviewed ? 'line-through decoration-slate-500' : ''}`}>{f.title}</p>
          <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400">
            <span className="inline-flex items-center gap-1 font-mono text-accent-300"><FileCode2 className="h-3 w-3" />{loc}</span>
            <span>{f.subcategory}</span>
            <span className="font-mono">{f.rule_id}</span>
            <span>confidence: <b className="text-slate-200">{f.confidence}</b></span>
          </p>
        </div>
        <div className="hidden items-center gap-2 sm:flex">
          <VerificationPill v={f.verification} />
          {f.review.reviewed && <span className="chip border-emerald-400/40 bg-emerald-400/10 text-emerald-300"><Check className="h-3 w-3" />Reviewed</span>}
          {aiNote && <span className="chip border-brand-400/40 bg-brand-500/10 text-brand-300"><Bot className="h-3 w-3" />AI note</span>}
        </div>
        <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-slate-400 transition ${open ? 'rotate-180' : ''}`} />
      </button>

      {open && (
        <div className="space-y-4 border-t border-ink-600/60 px-4 py-4">
          <div>
            <p className="label mb-2">Source evidence</p>
            <CodeEvidence f={f} />
            {f.occurrences.length > 0 && (
              <div className="mt-3">
                <p className="label mb-1.5">Other occurrences ({f.occurrences.length})</p>
                <ul className="space-y-1 text-xs">
                  {f.occurrences.map((o, i) => (
                    <li key={i} className="font-mono text-slate-400"><span className="text-accent-300">{o.file ? `${o.file}:` : ''}{o.line}</span> — {o.snippet}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
          <div className="grid gap-4 md:grid-cols-3">
            <div><p className="label mb-1">Explanation</p><p className="text-sm leading-relaxed text-slate-300">{f.explanation}</p></div>
            <div><p className="label mb-1">Potential impact</p><p className="text-sm leading-relaxed text-slate-300">{f.impact}</p></div>
            <div><p className="label mb-1 flex items-center gap-1"><Wrench className="h-3 w-3" />Suggested remediation</p><p className="text-sm leading-relaxed text-slate-300">{f.remediation}</p></div>
          </div>
          <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
            <VerificationPill v={f.verification} />
            <span className="chip border-ink-500 text-slate-300">Detected by: {f.detected_by.join(' + ')}</span>
            {f.cwe && <span className="chip border-ink-500 text-slate-300">{f.cwe}</span>}
            {f.tags.filter((t) => !t.startsWith('also:')).map((t) => <span key={t} className="chip border-ink-500 text-slate-300">{t}</span>)}
            <span className="font-mono">{f.id}</span>
          </div>

          {aiNote && (
            <div className="rounded-xl border border-brand-400/40 bg-brand-500/10 p-3 text-sm">
              <p className="mb-1 flex items-center gap-1.5 font-semibold text-brand-300"><Bot className="h-4 w-4" />AI-generated hypothesis — not verified by the scanner</p>
              <p className="text-slate-200">{aiNote.technical_implication}</p>
              {aiNote.likely_false_positive && <p className="mt-2 text-amber-300">AI suspects a false positive: {aiNote.false_positive_reason || 'no reason given'}</p>}
              {aiNote.suggested_fix_code && <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-950 p-3 font-mono text-xs text-slate-200">{aiNote.suggested_fix_code}</pre>}
            </div>
          )}

          <div className="flex flex-wrap items-end gap-3 border-t border-ink-600/50 pt-4">
            <div className="min-w-[200px] flex-1">
              <label className="label mb-1 block" htmlFor={`note-${f.id}`}>Reviewer note</label>
              <input id={`note-${f.id}`} className="input" placeholder="Optional note (saved with review status)" value={note} maxLength={500}
                onChange={(e) => setNote(e.target.value)} onBlur={() => { if (note !== f.review.note) save(f.review.reviewed, note) }} />
            </div>
            <button className={f.review.reviewed ? 'btn-secondary' : 'btn-primary'} disabled={busy} onClick={() => save(!f.review.reviewed)}>
              <Check className="h-4 w-4" />{f.review.reviewed ? 'Mark as open' : 'Mark as reviewed'}
            </button>
            <button className="btn-ghost" onClick={copy}><ClipboardCopy className="h-4 w-4" />{copied ? 'Copied' : 'Copy as Markdown'}</button>
          </div>
          {err && <p className="text-sm text-sev-critical">{err}</p>}
        </div>
      )}
    </article>
  )
}
