import type { Severity } from '../types'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']
export const SEV_COLOR: Record<Severity, string> = {
  critical: '#ff4d6d', high: '#ff8a4c', medium: '#f5c451', low: '#38bdf8', info: '#94a3b8',
}

export function scoreColor(score: number | null | undefined, invert = false): string {
  if (score === null || score === undefined) return '#64748b'
  const s = invert ? 100 - score : score
  if (s >= 85) return '#34d399'
  if (s >= 70) return '#22d3ee'
  if (s >= 50) return '#f5c451'
  if (s >= 30) return '#ff8a4c'
  return '#ff4d6d'
}

export function timeAgo(ts: number | null | undefined): string {
  if (!ts) return '—'
  const s = Math.max(0, Date.now() / 1000 - ts)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return new Date(ts * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' })
}

export function fmtDate(ts: number | null | undefined): string {
  return ts ? new Date(ts * 1000).toLocaleString() : '—'
}

export function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export const VERIFY_LABEL: Record<string, string> = {
  'static-match': 'Static match',
  'potential-risk': 'Potential risk',
  heuristic: 'Heuristic',
}

export const FALLBACK_REASONS: Record<string, string> = {
  missing_api_key: 'No GEMINI_API_KEY is configured',
  consent_required: 'Consent was not given',
  quota: 'Gemini quota / rate limit reached',
  network: 'Network failure reaching Gemini',
  timeout: 'Gemini request timed out',
  invalid_json: 'Gemini returned invalid JSON',
  model_error: 'Gemini model error',
  auth: 'Gemini rejected the API key',
  sdk_missing: 'Gemini SDK not installed',
  no_findings: 'Nothing to review',
}
