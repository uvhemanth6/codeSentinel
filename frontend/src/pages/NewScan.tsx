import { Github, Loader2, Package, ShieldAlert, UploadCloud } from 'lucide-react'
import { DragEvent, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ErrorBox, Notice, PageHeader } from '../components/ui'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'
import { fmtBytes } from '../utils/format'

type Tab = 'zip' | 'github' | 'sample'
const GH = /^https:\/\/(www\.)?github\.com\/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]+(\.git)?\/?(\/tree\/[\w./-]+)?$/

export default function NewScan() {
  const nav = useNavigate()
  const { data: health, error: healthError } = useAsync(() => api.health(), [])
  const [tab, setTab] = useState<Tab>('zip')
  const [file, setFile] = useState<File | null>(null)
  const [drag, setDrag] = useState(false)
  const [url, setUrl] = useState('')
  const [ai, setAi] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)
  const maxMb = health?.limits.max_upload_mb ?? 50
  const aiReady = health?.tools.gemini.configured ?? false

  const pick = (f?: File | null) => {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) return setError('Only .zip archives are supported.')
    if (f.size > maxMb * 1024 * 1024) return setError(`File is ${fmtBytes(f.size)}; the limit is ${maxMb} MB.`)
    setFile(f)
  }
  const onDrop = (e: DragEvent) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files?.[0]) }
  const urlOk = GH.test(url.trim())

  const go = async (fn: () => Promise<{ id: string }>) => {
    setBusy(true); setError(null)
    try { const { id } = await fn(); nav(`/scans/${id}`) } catch (e) { setError((e as Error).message); setBusy(false) }
  }

  const tabs: { id: Tab; label: string; icon: JSX.Element }[] = [
    { id: 'zip', label: 'Upload ZIP', icon: <UploadCloud className="h-4 w-4" /> },
    { id: 'github', label: 'GitHub URL', icon: <Github className="h-4 w-4" /> },
    { id: 'sample', label: 'Sample projects', icon: <Package className="h-4 w-4" /> },
  ]

  return (
    <div className="mx-auto max-w-3xl">
      <PageHeader title="New scan" subtitle="CodeSentinel reads your code statically. Nothing you provide is executed, built or installed." />
      {healthError && <div className="mb-4"><ErrorBox message={healthError} /></div>}
      <div className="mb-4 flex gap-1 rounded-2xl border border-ink-600/60 bg-ink-800/60 p-1.5">
        {tabs.map((t) => (
          <button key={t.id} onClick={() => { setTab(t.id); setError(null) }} className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2.5 text-sm font-semibold transition ${tab === t.id ? 'bg-gradient-to-r from-brand-600 to-brand-500 text-white shadow-glow' : 'text-slate-400 hover:text-white'}`}>{t.icon}{t.label}</button>
        ))}
      </div>

      <div className="card-pad space-y-5">
        {tab === 'zip' && (
          <>
            <div onDragOver={(e) => { e.preventDefault(); setDrag(true) }} onDragLeave={() => setDrag(false)} onDrop={onDrop} onClick={() => input.current?.click()} role="button" tabIndex={0}
              onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
              className={`flex cursor-pointer flex-col items-center rounded-2xl border-2 border-dashed px-6 py-12 text-center transition ${drag ? 'border-accent-400 bg-accent-400/5' : 'border-ink-500 hover:border-brand-400/60'}`}>
              <UploadCloud className="mb-3 h-10 w-10 text-brand-400" />
              {file ? <><p className="font-semibold text-white">{file.name}</p><p className="text-sm text-slate-400">{fmtBytes(file.size)}</p></> : <><p className="font-semibold text-white">Drop a .zip here or click to browse</p><p className="mt-1 text-sm text-slate-400">Max {maxMb} MB · up to {health?.limits.max_files ?? 5000} files · {health?.limits.max_uncompressed_mb ?? 200} MB uncompressed</p></>}
              <input ref={input} type="file" accept=".zip,application/zip" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
            </div>
            <p className="text-xs text-slate-500">Archives are extracted with path-traversal, symlink, zip-bomb and size protections. node_modules, .git, dist, build, venvs and binaries are skipped.</p>
          </>
        )}
        {tab === 'github' && (
          <>
            <label className="label block" htmlFor="gh">Public GitHub repository URL</label>
            <input id="gh" className="input" placeholder="https://github.com/owner/repository" value={url} onChange={(e) => setUrl(e.target.value)} />
            {url && !urlOk && <p className="text-sm text-amber-300">Use the form https://github.com/&lt;owner&gt;/&lt;repo&gt;</p>}
            <p className="text-xs text-slate-500">Only public repositories on github.com are accepted. The repository is downloaded as an archive (or shallow clone) into a temporary directory, scanned, and deleted. Hooks and build scripts are never run.</p>
          </>
        )}
        {tab === 'sample' && (
          <div className="grid gap-3 sm:grid-cols-3">
            {(health?.samples ?? []).map((s) => (
              <button key={s.id} disabled={busy} onClick={() => go(() => api.scanSample(s.id))} className="rounded-2xl border border-ink-500 bg-ink-850/60 p-4 text-left transition hover:border-accent-400/60 hover:bg-ink-700/60 disabled:opacity-50">
                <Package className="mb-2 h-6 w-6 text-accent-400" /><p className="font-semibold text-white">{s.label}</p><p className="mt-1 text-xs text-slate-400">Intentionally flawed demo — scanned for real.</p>
              </button>
            ))}
          </div>
        )}

        {tab !== 'sample' && (
          <>
            <div className={`rounded-xl border p-4 ${ai ? 'border-brand-400/40 bg-brand-500/10' : 'border-ink-600/60'}`}>
              <label className="flex items-start gap-3 text-sm text-slate-300">
                <input type="checkbox" className="mt-1 h-4 w-4 accent-brand-500" checked={ai} disabled={!aiReady} onChange={(e) => setAi(e.target.checked)} />
                <span><b className="text-white">Also run Gemini deep review</b> <span className="text-slate-500">(optional)</span><br />
                  {aiReady ? 'Sends redacted snippets of the top findings (not the repository) to Google Gemini after the scan. AI output is labelled as unverified.' : 'Unavailable: no GEMINI_API_KEY is configured on the backend. The deterministic engine runs regardless.'}</span>
              </label>
            </div>
            {error && <Notice tone="warn">{error}</Notice>}
            <button className="btn-primary w-full py-3" disabled={busy || (tab === 'zip' ? !file : !urlOk)}
              onClick={() => go(() => (tab === 'zip' ? api.uploadZip(file!, ai) : api.scanGithub(url.trim(), ai)))}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}{busy ? 'Starting scan…' : 'Start audit'}
            </button>
          </>
        )}
        {tab === 'sample' && error && <Notice tone="warn">{error}</Notice>}
      </div>
    </div>
  )
}
