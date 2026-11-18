# Architecture

```
React UI ──/api──► Flask routes ──► runner (ingest: zip | github | sample)
                                      └► pipeline: discovery → languages → structure
                                           → analyzers by stage (security | slop | gaps | loose_ends)
                                           → normalize → dedupe → priority → scoring → deterministic review
                                      └► SQLite (scans, reviews, settings)    └► optional Gemini review (explicit consent)
```

* `app/models/finding.py` – the common Finding format. `app/analyzers/base.py` – plugin interface + registry.
* `app/services/languages.py` – language registry (extend with `register_language`).
* `app/security/rules.py` – declarative rule catalogue (explanation, impact, remediation per rule).
* `app/services/scoring.py` – documented formulas; `app/services/normalize.py` – dedupe/merge policy.
* `app/ai/` – `deterministic.py` (always available) and `gemini.py` (optional, validated, redacted).

## API (all under `/api`)

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | tools, limits, languages, samples |
| POST | `/scans/upload` · `/scans/github` · `/scans/sample` | start a scan (202 + id) |
| GET | `/scans` · `/scans/<id>` · DELETE `/scans/<id>` | history / status+result / delete |
| GET | `/scans/<id>/findings` | filters: `category,severity,subcategory,source,verification,reviewed,q,file,sort,limit,offset` |
| PATCH | `/scans/<id>/findings/<fid>/review` | `{reviewed, note}` |
| GET | `/scans/<id>/files` · `/scans/<id>/report?format=json|md|html` | file table / export |
| POST | `/scans/<id>/ai/preview` · `/scans/<id>/ai/review` | disclosure preview / Gemini review (`consent:true`) |
| GET/PUT/POST | `/settings` · `/settings/reset` | weights, thresholds, norms |
| GET | `/dashboard` | latest-scan aggregates + recent scans |

## Adding an analyzer

```python
@register
class MyAnalyzer(Analyzer):
    name, stage, languages = "my-analyzer", "gaps", ("Go",)
    def analyze_file(self, sf, ctx): return [build_finding(sf, rule_id=..., ...)]
```
Import the module in `services/pipeline.py`; nothing else changes.
