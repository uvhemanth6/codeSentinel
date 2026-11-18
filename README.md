# CodeSentinel

> **Find the flaws. Fix the code. Ship with confidence.**

CodeSentinel is an AI-assisted, **architecture-independent code auditing agent** built for the **Mycrobo** hackathon.
It scans a repository (ZIP upload or public GitHub URL) and reports **security risks**, **code slop**, **coding gaps** and
**loose ends** — each finding with rule ID, file, line, source evidence, explanation, impact, remediation, confidence,
detection source and verification status — plus a transparent repository health score.

The deterministic engine works **without any AI key**. Gemini reasoning is optional, opt-in and validated.

> Official requirement: *"a simple agent for security and pulling slop as well as coding gaps and loose ends which is architecture agnostic."*

| Requirement | Where it lives |
|---|---|
| Security | `security/rules.py` (47 regex rules), `analyzers/python_ast_security.py`, Bandit, optional Semgrep, HTML/YAML/SQL/Docker analyzers |
| Code slop | `analyzers/slop.py` – duplicate functions/blocks, long functions, nesting, complexity, unused imports/vars/deps, dead code, redundant comments, naming, wrappers |
| Coding gaps | `analyzers/gaps_python.py`, `gaps_clike.py`, `config_files.py` – empty/placeholder code, swallowed errors, missing validation/timeouts |
| Loose ends | `analyzers/loose_ends.py` + debug-leftover rules – TODO/FIXME/XXX/HACK, print/console.log/debugger, dev settings |
| Architecture agnostic | see below |

## Quick start

Requirements: Python 3.11+, Node 18+.

```bash
# 1. backend
cd backend
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example ../.env                              # optionally add GEMINI_API_KEY
python run.py                                           # http://127.0.0.1:5000
```

```bash
# 2. frontend (dev server with API proxy)
cd frontend
npm install
npm run dev                                             # http://localhost:5173
```

```bash
# or: build once and let Flask serve the UI on :5000
cd frontend && npm run build   # then open http://127.0.0.1:5000
```

Optional extra engine: `pip install semgrep` (auto-detected, runs the bundled local rules in `backend/rules/`).

### Tests

```bash
cd backend && python -m pytest tests -q        # 90 tests: analyzers, ingestion safety, scoring, AI, API integration
cd frontend && npm run build                   # type-check + production build
```

## Pipeline (14 stages, live progress in the UI)

1 ingestion → 2 file discovery → 3 language identification → 4 structure analysis → 5 security scanning →
6 code-slop detection → 7 coding-gap detection → 8 loose-end detection → 9 normalization → 10 deduplication →
11 AI reasoning (deterministic; Gemini on request) → 12 severity prioritization → 13 health scoring → 14 report generation.

Analyzers are **plugins**: subclass `Analyzer`, set `stage`, decorate with `@register`
(`backend/app/analyzers/base.py`). Each returns findings in the common `Finding` format. A failing analyzer is
recorded in the scan report and never aborts the scan.

## Why it is architecture agnostic

* **No required layout** — files are discovered recursively; nothing assumes `src/`, MVC, a framework or a build tool.
* **Extensible language registry** (`services/languages.py`) — a new language is one `register_language(...)` call; the
  generic analyzers (secrets, loose ends, duplication) apply immediately, and the pipeline is unchanged.
* **Honest depth levels** — Python, Java, JavaScript, TypeScript, HTML, CSS, SQL, JSON, YAML have dedicated analyzers;
  Go, Rust, PHP, Ruby, C/C++, C#, Kotlin, Swift, Shell, properties/env/XML/Dockerfile get generic analysis
  (marked *partial*); unknown types are reported as **unsupported**, never silently dropped.
* **Framework detection is observational** (Flask, Django, FastAPI, Spring Boot, Express, React, Node.js) and only
  adds context; rules do not depend on it.
* **Layered techniques** — AST (Python), comment/string-aware token views and brace matching (C-like languages),
  regex rules, config parsers, and external tools (Bandit/Semgrep) where available.

## Security of the scanner itself

* ZIP: path-traversal/absolute-path rejection, symlink skipping, entry-count / declared-size / **streamed actual-size** /
  compression-ratio limits, encrypted archives refused, ignored directories never extracted, temp dirs always deleted.
* GitHub: only `https://github.com/<owner>/<repo>` (strict regex; no userinfo, ports, IPs, other hosts, queries);
  requests go only to fixed GitHub hosts built by the server; redirects followed manually against an allow-list;
  streamed with size cap and timeout; shallow-clone fallback runs with hooks disabled and no `.git` kept.
* Uploaded or fetched code is **never executed** (Bandit/Semgrep only parse it).
* Secrets found in code are **masked** in stored findings, reports and AI payloads.
* Reports escape all repository-derived text (HTML export is XSS-safe).

## AI (optional, Google Gemini)

Uses the official `google-genai` SDK, configured via `GEMINI_API_KEY` (server environment only).

* **User-controlled and disclosed** — a consent checkbox is required; *Preview data* shows the exact payload.
  Only ≤15 redacted finding snippets are sent — never the repository.
* **Untrusted input** — repository text is placed in a delimited data block; the model is told to treat it as data.
* **Validated output** — strict JSON validation; unknown finding IDs dropped; file paths/line numbers are **never**
  taken from the model; text length-capped. Output is labelled *AI-generated hypothesis — not verified* and is kept
  separate from scanner results.
* **Graceful fallback** for missing key, quota, network, timeout, invalid JSON and model errors — the deterministic
  review (executive summary, remediation plan, architectural risks, related-issue groups) is shown with the reason.

## Findings & scoring

Severity: critical / high / medium / low / info. **Verification status** — `static-match` (deterministic construct),
`potential-risk` (needs data-flow/human confirmation), `heuristic` (measured quality indicator).
Duplicate detections by several tools on the same `(file, line, family)` are merged (corroboration raises confidence).

Four dimension scores — Security, Code Quality, Completeness, Maintainability — each finding counted in **exactly one**:
`score = 100·exp(−points / (norm·(1 + KLOC·size_factor)))`, `points = Σ severity_points × confidence_factor`.
Overall health = weighted mean (weights configurable in Settings). **Code Slop Score** (0–100, higher = worse)
= `100·(1 − exp(−slop points per 100 LOC / norm))`. Every score ships with its own explanation in the UI.
Scores are heuristic indicators, **not a security certification**. CodeSentinel does not try to guess whether code was
AI-generated — it only measures concrete patterns.

## Project layout

```
CodeSentinel/
├── backend/        Flask API, pipeline, analyzers, AI layer, SQLite store, pytest suite
├── frontend/       React + Vite + TypeScript + Tailwind + Recharts + Lucide
├── sample_projects/  intentionally flawed Python / Java / JavaScript demos
├── docs/           architecture & API notes
└── reports/        place for exported reports
```

## Limitations (honest notes)

* Static analysis only: no taint tracking across files; "potential risk" findings need human triage.
* Java/JS/TS analysis is token/regex based (no full parser), so metrics there are approximations.
* Semgrep is optional and was not available in the development environment; its integration is covered by a parser
  unit path only when installed.
* GitHub retrieval needs outbound access to github.com / api.github.com.
* The Gemini integration is covered by mocked tests; it has not been exercised against the live API in CI.
