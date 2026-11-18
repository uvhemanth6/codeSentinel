import { AlertTriangle, CheckCircle2, ChevronDown, Info, Loader2, ShieldQuestion } from 'lucide-react'
import { ReactNode, useState } from 'react'
import type { Severity, Verification } from '../types'
import { SEV_COLOR, VERIFY_LABEL, scoreColor } from '../utils/format'

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-3 py-16 text-slate-400">
      <Loader2 className="h-5 w-5 animate-spin text-accent-400" />
      {label && <span className="text-sm">{label}</span>}
    </div>
  )
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="card-pad flex items-start gap-3 border-sev-critical/40" role="alert">
      <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-sev-critical" />
      <div className="flex-1">
        <p className="font-semibold text-white">Something went wrong</p>
        <p className="mt-1 text-sm text-slate-400">{message}</p>
      </div>
      {onRetry && <button className="btn-secondary" onClick={onRetry}>Retry</button>}
    </div>
  )
}

export function EmptyState({ icon, title, children, action }: { icon?: ReactNode; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="card-pad flex flex-col items-center px-6 py-14 text-center">
      <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-ink-700 text-accent-400">{icon ?? <Info />}</div>
      <h3 className="text-lg font-semibold text-white">{title}</h3>
      {children && <div className="mt-2 max-w-md text-sm text-slate-400">{children}</div>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const c = SEV_COLOR[severity]
  return (
    <span className="inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide"
      style={{ color: c, background: `${c}1f`, border: `1px solid ${c}55` }}>
      {severity}
    </span>
  )
}

export function VerificationPill({ v }: { v: Verification }) {
  const map: Record<Verification, string> = {
    'static-match': 'border-emerald-400/40 text-emerald-300 bg-emerald-400/10',
    'potential-risk': 'border-amber-400/40 text-amber-300 bg-amber-400/10',
    heuristic: 'border-slate-400/30 text-slate-300 bg-slate-400/10',
  }
  const Icon = v === 'static-match' ? CheckCircle2 : v === 'potential-risk' ? ShieldQuestion : Info
  return (
    <span className={`chip ${map[v]}`} title={v === 'static-match' ? 'Deterministic pattern/AST match' : v === 'potential-risk' ? 'Suspected; needs human confirmation' : 'Measured quality indicator'}>
      <Icon className="h-3 w-3" />{VERIFY_LABEL[v]}
    </span>
  )
}

export function StatCard({ label, value, sub, color, icon }: { label: string; value: ReactNode; sub?: ReactNode; color?: string; icon?: ReactNode }) {
  return (
    <div className="card-pad animate-fadeUp">
      <div className="flex items-center justify-between">
        <span className="label">{label}</span>
        {icon && <span className="text-slate-500">{icon}</span>}
      </div>
      <div className="mt-2 text-3xl font-extrabold tracking-tight" style={{ color: color ?? '#fff' }}>{value}</div>
      {sub && <div className="mt-1 text-xs text-slate-400">{sub}</div>}
    </div>
  )
}

export function ScoreRing({ score, size = 120, label, invert = false, sub }: { score: number | null; size?: number; label: string; invert?: boolean; sub?: string }) {
  const r = size / 2 - 9
  const c = 2 * Math.PI * r
  const color = scoreColor(score, invert)
  const pct = score === null ? 0 : Math.max(0, Math.min(100, score))
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1a2447" strokeWidth={9} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={9} strokeLinecap="round"
            strokeDasharray={c} strokeDashoffset={c - (c * pct) / 100} style={{ transition: 'stroke-dashoffset .8s ease, stroke .3s' }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-extrabold text-white" style={{ fontSize: size * 0.28 }}>{score ?? '—'}</span>
          {sub && <span className="text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap" style={{ color }}>{sub}</span>}
        </div>
      </div>
      <span className="text-center text-xs font-semibold uppercase tracking-wider text-slate-400">{label}</span>
    </div>
  )
}

export function Collapsible({ title, children, defaultOpen = false }: { title: ReactNode; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="rounded-xl border border-ink-600/60 bg-ink-850/60">
      <button className="flex w-full items-center justify-between px-4 py-3 text-left text-sm font-semibold text-slate-200" onClick={() => setOpen(!open)} aria-expanded={open}>
        {title}
        <ChevronDown className={`h-4 w-4 text-slate-400 transition ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && <div className="border-t border-ink-600/60 px-4 py-3 text-sm text-slate-300">{children}</div>}
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="h-page">{title}</h1>
        {subtitle && <p className="mt-1 max-w-2xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}

export function Notice({ tone = 'info', children }: { tone?: 'info' | 'warn' | 'ai'; children: ReactNode }) {
  const tones = {
    info: 'border-accent-400/30 bg-accent-400/5 text-accent-300',
    warn: 'border-amber-400/30 bg-amber-400/5 text-amber-200',
    ai: 'border-brand-400/40 bg-brand-500/10 text-brand-300',
  }
  return <div className={`rounded-xl border px-4 py-3 text-sm ${tones[tone]}`}>{children}</div>
}
