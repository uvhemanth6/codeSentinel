import { CheckCircle2, Circle, Loader2, XCircle } from 'lucide-react'
import type { Stage } from '../types'

export default function StageTracker({ stages }: { stages: Stage[] }) {
  const done = stages.filter((s) => s.status === 'done').length
  return (
    <div className="card-pad">
      <div className="mb-4 flex items-center justify-between">
        <h3 className="font-semibold text-white">Audit pipeline</h3>
        <span className="text-xs text-slate-400">{done}/{stages.length} stages complete</span>
      </div>
      <div className="mb-5 h-1.5 overflow-hidden rounded-full bg-ink-700">
        <div className="h-full rounded-full bg-gradient-to-r from-brand-500 to-accent-400 transition-all duration-500" style={{ width: `${(done / stages.length) * 100}%` }} />
      </div>
      <ol className="grid gap-2 sm:grid-cols-2">
        {stages.map((s, i) => (
          <li key={s.key} className={`flex items-start gap-3 rounded-xl border px-3 py-2.5 ${s.status === 'running' ? 'border-accent-400/50 bg-accent-400/5' : s.status === 'failed' ? 'border-sev-critical/40 bg-sev-critical/5' : 'border-ink-600/50'}`}>
            <span className="mt-0.5">
              {s.status === 'done' ? <CheckCircle2 className="h-4 w-4 text-emerald-400" /> : s.status === 'running' ? <Loader2 className="h-4 w-4 animate-spin text-accent-400" /> : s.status === 'failed' ? <XCircle className="h-4 w-4 text-sev-critical" /> : <Circle className="h-4 w-4 text-slate-600" />}
            </span>
            <div className="min-w-0">
              <p className={`text-sm font-medium ${s.status === 'pending' ? 'text-slate-500' : 'text-slate-100'}`}>{i + 1}. {s.label}</p>
              {s.detail && <p className="truncate text-xs text-slate-400" title={s.detail}>{s.detail}</p>}
            </div>
          </li>
        ))}
      </ol>
    </div>
  )
}
