import type { AiPreview, Dashboard, FileRow, FindingsPage, GeminiReview, Health, Scan, Settings } from '../types'

const BASE = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${BASE}${path}`, init)
  } catch {
    throw new ApiError('Cannot reach the CodeSentinel backend. Is it running on port 5000?', 0)
  }
  const text = await res.text()
  let data: any = null
  try { data = text ? JSON.parse(text) : null } catch { /* non-JSON body */ }
  if (!res.ok) throw new ApiError(data?.error ?? `Request failed (${res.status})`, res.status)
  return data as T
}

const json = (method: string, body?: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: body === undefined ? undefined : JSON.stringify(body),
})

export const api = {
  health: () => request<Health>('/health'),
  dashboard: () => request<Dashboard>('/dashboard'),
  listScans: () => request<{ scans: Scan[] }>('/scans').then((r) => r.scans),
  getScan: (id: string) => request<Scan>(`/scans/${id}`),
  deleteScan: (id: string) => request<{ deleted: boolean }>(`/scans/${id}`, { method: 'DELETE' }),
  uploadZip: (file: File, aiConsent: boolean) => {
    const fd = new FormData()
    fd.append('file', file)
    fd.append('ai_consent', String(aiConsent))
    return request<{ id: string }>('/scans/upload', { method: 'POST', body: fd })
  },
  scanGithub: (url: string, aiConsent: boolean) => request<{ id: string }>('/scans/github', json('POST', { url, ai_consent: aiConsent })),
  scanSample: (name: string) => request<{ id: string }>('/scans/sample', json('POST', { name })),
  findings: (id: string, params: Record<string, string | number | undefined>) => {
    const q = new URLSearchParams()
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== '') q.set(k, String(v)) })
    return request<FindingsPage>(`/scans/${id}/findings?${q}`)
  },
  review: (id: string, fid: string, reviewed: boolean, note: string) =>
    request<{ reviewed: boolean; note: string }>(`/scans/${id}/findings/${fid}/review`, json('PATCH', { reviewed, note })),
  files: (id: string) => request<{ files: FileRow[]; skipped: { counts: Record<string, number> }; unsupported: { extension: string; files: number }[] }>(`/scans/${id}/files`),
  reportUrl: (id: string, format: 'json' | 'md' | 'html') => `${BASE}/scans/${id}/report?format=${format}`,
  aiPreview: (id: string, limit: number) => request<AiPreview>(`/scans/${id}/ai/preview`, json('POST', { limit })),
  aiReview: (id: string, limit: number) => request<GeminiReview>(`/scans/${id}/ai/review`, json('POST', { consent: true, limit })),
  settings: () => request<{ settings: Settings; defaults: Settings; ai: Health['tools']['gemini'] }>('/settings'),
  saveSettings: (s: Partial<Settings>) => request<{ settings: Settings }>('/settings', json('PUT', s)),
  resetSettings: () => request<{ settings: Settings }>('/settings/reset', json('POST')),
}
