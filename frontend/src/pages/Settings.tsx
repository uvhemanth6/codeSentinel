import { CheckCircle2, KeyRound, RotateCcw, Save, XCircle } from 'lucide-react'
import { useEffect, useState } from 'react'
import { ErrorBox, Notice, PageHeader, Spinner } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import type { Settings } from '../types'

const WEIGHT_LABEL: Record<string, string> = { security: 'Security', quality: 'Code quality', completeness: 'Completeness', maintainability: 'Maintainability' }
const THRESH_LABEL: Record<string, string> = {
  long_function_lines: 'Long function (lines)', very_long_function_lines: 'Very long function (lines)', max_complexity: 'Max cyclomatic complexity',
  very_high_complexity: 'Very high complexity', max_nesting: 'Max nesting depth', max_params: 'Max parameters',
  duplicate_window_lines: 'Repeated-block window (lines)', min_duplicate_function_lines: 'Min duplicate function (lines)',
}

export default function SettingsPage() {
  const s = useAsync(() => api.settings(), [])
  const h = useAsync(() => api.health(), [])
  const [draft, setDraft] = useState<Settings | null>(null)
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null)
  const [busy, setBusy] = useState(false)
  useEffect(() => { if (s.data) setDraft(structuredClone(s.data.settings)) }, [s.data])

  if (s.error) return <ErrorBox message={s.error} onRetry={s.reload} />
  if (!draft || !s.data) return <Spinner label="Loading settings…" />
  const sumW = Object.values(draft.weights).reduce((a, b) => a + b, 0) || 1

  const set = (section: keyof Settings, key: string, v: number) => setDraft({ ...draft, [section]: { ...(draft[section] as Record<string, number>), [key]: v } } as Settings)
  const save = async () => {
    setBusy(true); setMsg(null)
    try { const r = await api.saveSettings(draft); setDraft(r.settings); setMsg({ ok: true, text: 'Settings saved. They apply to new scans.' }) } catch (e) { setMsg({ ok: false, text: (e as Error).message }) } finally { setBusy(false) }
  }
  const reset = async () => {
    setBusy(true); setMsg(null)
    try { const r = await api.resetSettings(); setDraft(r.settings); setMsg({ ok: true, text: 'Defaults restored.' }) } catch (e) { setMsg({ ok: false, text: (e as Error).message }) } finally { setBusy(false) }
  }
  const ai = s.data.ai

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" subtitle="Tune how scores are computed. Changes apply to future scans; each scan stores the settings it used."
        actions={<><button className="btn-secondary" onClick={reset} disabled={busy}><RotateCcw className="h-4 w-4" />Reset to defaults</button><button className="btn-primary" onClick={save} disabled={busy}><Save className="h-4 w-4" />Save settings</button></>} />
      {msg && <Notice tone={msg.ok ? 'info' : 'warn'}>{msg.text}</Notice>}

      <section className="card-pad">
        <h2 className="mb-1 font-semibold text-white">Health score weights</h2>
        <p className="mb-4 text-sm text-slate-400">Overall health is the weighted mean of the four dimension scores. Weights are normalised automatically.</p>
        <div className="grid gap-5 md:grid-cols-2">
          {Object.keys(WEIGHT_LABEL).map((k) => (
            <div key={k}>
              <div className="mb-1 flex justify-between text-sm"><label htmlFor={`w-${k}`} className="text-slate-300">{WEIGHT_LABEL[k]}</label><b className="text-white">{Math.round(((draft.weights[k] ?? 0) / sumW) * 100)}%</b></div>
              <input id={`w-${k}`} type="range" min={0} max={1} step={0.05} value={draft.weights[k] ?? 0} onChange={(e) => set('weights', k, Number(e.target.value))} className="w-full accent-brand-500" />
            </div>
          ))}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="card-pad">
          <h2 className="mb-1 font-semibold text-white">Severity penalty points</h2>
          <p className="mb-4 text-sm text-slate-400">Points added to a dimension's penalty for each finding.</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {Object.keys(draft.severity_points).map((k) => <NumberField key={k} label={k} value={draft.severity_points[k]} onChange={(v) => set('severity_points', k, v)} />)}
          </div>
        </div>
        <div className="card-pad">
          <h2 className="mb-1 font-semibold text-white">Detection thresholds</h2>
          <p className="mb-4 text-sm text-slate-400">When code-slop metrics become findings.</p>
          <div className="grid grid-cols-2 gap-3">
            {Object.keys(draft.thresholds).map((k) => <NumberField key={k} label={THRESH_LABEL[k] ?? k} value={draft.thresholds[k]} onChange={(v) => set('thresholds', k, v)} />)}
          </div>
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-2">
        <div className="card-pad">
          <h2 className="mb-1 font-semibold text-white">Score normalisation</h2>
          <p className="mb-4 text-sm text-slate-400">Higher norms make a dimension more forgiving. Scores shrink further as codebases grow (size factor).</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            {Object.keys(draft.norms).map((k) => <NumberField key={k} label={`${k} norm`} value={draft.norms[k]} onChange={(v) => set('norms', k, v)} />)}
            <NumberField label="size factor" value={draft.size_factor} step={0.1} onChange={(v) => setDraft({ ...draft, size_factor: v })} />
          </div>
        </div>
        <div className="card-pad">
          <h2 className="mb-3 flex items-center gap-2 font-semibold text-white"><KeyRound className="h-4 w-4 text-brand-400" />AI configuration (Gemini)</h2>
          <p className="flex items-center gap-2 text-sm">{ai.configured ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-amber-300" />}{ai.configured ? 'GEMINI_API_KEY is configured on the backend.' : 'No GEMINI_API_KEY found — AI features are disabled.'}</p>
          <dl className="mt-3 grid grid-cols-2 gap-1 text-sm text-slate-400"><dt>Model</dt><dd className="font-mono text-slate-200">{ai.model}</dd><dt>SDK</dt><dd className="font-mono text-slate-200">{ai.sdk}</dd><dt>Timeout</dt><dd className="text-slate-200">{ai.timeout_seconds}s</dd></dl>
          <Notice tone="info"><span className="block pt-0">The API key is read from the server environment only and is never exposed to the browser. Set <code className="font-mono">GEMINI_API_KEY</code> in <code className="font-mono">.env</code> and restart the backend. Without it, the deterministic engine does all the work.</span></Notice>
        </div>
      </section>

      <section className="card-pad">
        <h2 className="mb-3 font-semibold text-white">Engine status</h2>
        {h.data && (
          <div className="grid gap-6 md:grid-cols-2">
            <ul className="space-y-2 text-sm">
              <Tool name="Bandit (Python security)" ok={h.data.tools.bandit} />
              <Tool name="Semgrep (optional)" ok={h.data.tools.semgrep} off="not installed — pip install semgrep" />
              <Tool name="Gemini AI (optional)" ok={h.data.tools.gemini.configured} off="no API key" />
              <li className="text-slate-400">{h.data.engine.security_rules} custom security rules · {h.data.engine.analyzers.length} analyzers · Python {h.data.python}</li>
            </ul>
            <div>
              <p className="label mb-2">Language support</p>
              <div className="flex flex-wrap gap-1.5">{h.data.languages.map((l) => <span key={l.name} className={`chip ${l.support === 'full' ? 'border-brand-400/40 text-brand-300' : 'border-accent-400/30 text-accent-300'}`}>{l.name}{l.support === 'full' ? '' : ' (partial)'}</span>)}</div>
              <p className="mt-2 text-xs text-slate-500">Unknown file types are reported as unsupported, never silently ignored.</p>
            </div>
          </div>
        )}
      </section>
    </div>
  )
}

function NumberField({ label, value, onChange, step = 1 }: { label: string; value: number; onChange: (v: number) => void; step?: number }) {
  return (
    <label className="block text-xs text-slate-400"><span className="mb-1 block capitalize">{label}</span>
      <input type="number" min={0} step={step} className="input py-2" value={value} onChange={(e) => onChange(Number(e.target.value))} />
    </label>
  )
}
function Tool({ name, ok, off }: { name: string; ok: boolean; off?: string }) {
  return <li className="flex items-center gap-2 text-slate-200">{ok ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : <XCircle className="h-4 w-4 text-slate-500" />}{name}{!ok && off && <span className="text-xs text-slate-500">— {off}</span>}</li>
}
