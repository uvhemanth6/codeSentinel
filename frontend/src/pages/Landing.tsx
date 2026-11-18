import { ArrowRight, Bot, Bug, CheckCircle2, FileWarning, GitBranch, Globe2, Layers, LockKeyhole, ShieldAlert, Sparkles, Upload, Wrench } from 'lucide-react'
import { Link } from 'react-router-dom'
import Logo from '../components/Logo'
import { useAsync } from '../hooks/useAsync'
import { api } from '../services/api'

const PIPELINE = ['Repository ingestion', 'File discovery', 'Language identification', 'Structure analysis', 'Security scanning', 'Code slop detection', 'Coding gap detection', 'Loose-end detection', 'Normalization', 'Deduplication', 'AI reasoning', 'Prioritization', 'Health scoring', 'Report generation']

const FEATURES = [
  { icon: ShieldAlert, color: 'text-sev-critical', title: 'Security', text: 'Hard-coded secrets, SQL/command injection, unsafe deserialization, XSS, path traversal, weak crypto, insecure transport, unsafe auth — via custom rules, Python AST, Bandit and optional Semgrep.' },
  { icon: Bug, color: 'text-brand-400', title: 'Code slop', text: 'Duplicate functions and blocks, long or deeply nested code, high complexity, dead code, unused imports and dependencies — measured, not guessed.' },
  { icon: FileWarning, color: 'text-amber-300', title: 'Coding gaps', text: 'Missing validation, swallowed errors, empty implementations, placeholder returns and unfinished API endpoints. Abstract methods and interfaces are respected.' },
  { icon: Wrench, color: 'text-accent-400', title: 'Loose ends', text: 'TODO / FIXME / XXX / HACK markers, debug prints, console.log, debugger statements and development-only configuration left in the code.' },
]

export default function Landing() {
  const { data: health } = useAsync(() => api.health(), [])
  return (
    <div className="min-h-screen">
      <header className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5">
        <Logo />
        <nav className="flex items-center gap-2">
          <Link to="/history" className="btn-ghost hidden sm:inline-flex">History</Link>
          <Link to="/dashboard" className="btn-secondary">Dashboard</Link>
          <Link to="/scan/new" className="btn-primary hidden sm:inline-flex">Start a scan</Link>
        </nav>
      </header>

      <section className="mx-auto max-w-5xl px-5 pb-16 pt-14 text-center sm:pt-24">
        <span className="chip mb-6 border-brand-400/40 bg-brand-500/10 text-brand-300"><Sparkles className="h-3.5 w-3.5" />Built for the Mycrobo hackathon</span>
        <h1 className="text-4xl font-extrabold leading-[1.08] tracking-tight text-white sm:text-6xl">
          Find the flaws.<br />
          <span className="bg-gradient-to-r from-brand-400 via-brand-300 to-accent-400 bg-clip-text text-transparent">Fix the code.</span><br />
          Ship with confidence.
        </h1>
        <p className="mx-auto mt-6 max-w-2xl text-lg text-slate-400">
          CodeSentinel is an AI-assisted, architecture-independent code auditing agent. It scans repositories for security risks, low-quality code patterns, incomplete implementations and development loose ends — with source evidence for every finding.
        </p>
        <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
          <Link to="/scan/new" className="btn-primary px-6 py-3 text-base">Scan a repository<ArrowRight className="h-4 w-4" /></Link>
          <Link to="/dashboard" className="btn-secondary px-6 py-3 text-base">View dashboard</Link>
        </div>
        <ul className="mt-8 flex flex-wrap justify-center gap-x-6 gap-y-2 text-sm text-slate-400">
          <li className="flex items-center gap-1.5"><CheckCircle2 className="h-4 w-4 text-emerald-400" />Works without an AI key</li>
          <li className="flex items-center gap-1.5"><CheckCircle2 className="h-4 w-4 text-emerald-400" />Never executes your code</li>
          <li className="flex items-center gap-1.5"><CheckCircle2 className="h-4 w-4 text-emerald-400" />ZIP or public GitHub URL</li>
        </ul>
      </section>

      {/* example finding, clearly labelled */}
      <section className="mx-auto max-w-4xl px-5 pb-20">
        <div className="card overflow-hidden shadow-glow">
          <div className="flex items-center justify-between border-b border-ink-600/60 px-4 py-2.5 text-xs text-slate-400"><span>Illustrative example of a finding (not a real scan)</span><span className="chip border-sev-critical/40 text-sev-critical">HIGH</span></div>
          <div className="grid gap-0 md:grid-cols-2">
            <pre className="overflow-x-auto bg-ink-950 p-4 font-mono text-[12.5px] leading-6 text-slate-300"><span className="text-slate-600">24  </span>{'def find_user(cur, name):\n'}<span className="bg-sev-critical/15 text-slate-100"><span className="text-slate-600">25  </span>{'    cur.execute(f"SELECT * FROM users WHERE name=\'{name}\'")'}</span>{'\n'}<span className="text-slate-600">26  </span>{'    return cur.fetchall()'}</pre>
            <div className="space-y-2 p-4 text-sm">
              <p className="font-semibold text-white">SQL executed with dynamically built query</p>
              <p className="text-slate-400">User-controlled values reach the query text, enabling SQL injection.</p>
              <p className="text-xs text-slate-500">Detected by: python-ast + bandit · CWE-89 · static match · confidence high</p>
              <p className="rounded-lg bg-emerald-400/10 p-2 text-xs text-emerald-300">Fix: pass parameters separately — cur.execute(sql, (name,))</p>
            </div>
          </div>
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-20">
        <h2 className="mb-2 text-center text-3xl font-bold text-white">One agent, four kinds of problems</h2>
        <p className="mx-auto mb-10 max-w-2xl text-center text-slate-400">Every finding carries its rule, file, line, code evidence, impact, remediation, confidence and verification status.</p>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {FEATURES.map((f) => (
            <div key={f.title} className="card-pad transition hover:-translate-y-1 hover:border-brand-400/40"><f.icon className={`mb-3 h-7 w-7 ${f.color}`} /><h3 className="mb-1.5 text-lg font-semibold text-white">{f.title}</h3><p className="text-sm leading-relaxed text-slate-400">{f.text}</p></div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-5 pb-20">
        <div className="card-pad">
          <h2 className="mb-1 text-2xl font-bold text-white">A real multi-stage pipeline</h2>
          <p className="mb-6 text-sm text-slate-400">Each scan runs these 14 stages and reports live progress. Analyzers are plugins: add one and the pipeline picks it up.</p>
          <ol className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {PIPELINE.map((p, i) => <li key={p} className="flex items-center gap-3 rounded-xl border border-ink-600/50 bg-ink-850/50 px-3 py-2.5 text-sm text-slate-300"><span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-md bg-brand-500/20 text-xs font-bold text-brand-300">{i + 1}</span>{p}</li>)}
          </ol>
        </div>
      </section>

      <section className="mx-auto grid max-w-7xl gap-4 px-5 pb-20 lg:grid-cols-3">
        <div className="card-pad"><Globe2 className="mb-3 h-6 w-6 text-accent-400" /><h3 className="mb-2 text-lg font-semibold text-white">Architecture agnostic</h3><p className="text-sm leading-relaxed text-slate-400">No required folder layout, framework or build system. Files are discovered recursively, languages come from an extensible registry, and unknown types are reported as unsupported rather than ignored.</p>
          {health && <p className="mt-3 text-xs text-slate-500">{health.languages.length} languages registered · {health.engine.security_rules} security rules · {health.engine.analyzers.length} analyzers</p>}</div>
        <div className="card-pad"><Bot className="mb-3 h-6 w-6 text-brand-400" /><h3 className="mb-2 text-lg font-semibold text-white">AI you can trust</h3><p className="text-sm leading-relaxed text-slate-400">Optional Gemini reasoning is opt-in, sends only redacted snippets, validates every response, can never invent file paths or confirmed vulnerabilities, and falls back to deterministic analysis on any failure.</p></div>
        <div className="card-pad"><LockKeyhole className="mb-3 h-6 w-6 text-emerald-400" /><h3 className="mb-2 text-lg font-semibold text-white">Safe by design</h3><p className="text-sm leading-relaxed text-slate-400">ZIP-slip, symlink and zip-bomb protection; strict GitHub URL allow-listing against SSRF; temporary files deleted after every scan; uploaded code is never executed.</p></div>
      </section>

      <section className="mx-auto max-w-4xl px-5 pb-24 text-center">
        <div className="card-pad bg-gradient-to-br from-brand-600/20 to-accent-500/10 py-12">
          <h2 className="text-3xl font-bold text-white">Audit your code in a minute</h2>
          <p className="mx-auto mt-2 max-w-lg text-slate-300">Upload a ZIP or paste a public repository URL.</p>
          <div className="mt-6 flex flex-wrap justify-center gap-3"><Link to="/scan/new" className="btn-primary px-6 py-3"><Upload className="h-4 w-4" />Upload a ZIP</Link><Link to="/scan/new" className="btn-secondary px-6 py-3"><GitBranch className="h-4 w-4" />Use a GitHub URL</Link></div>
        </div>
      </section>

      <footer className="border-t border-ink-600/50 py-8 text-center text-xs text-slate-500"><Layers className="mx-auto mb-2 h-4 w-4" />CodeSentinel · scores are heuristic indicators, not a security certification.</footer>
    </div>
  )
}
