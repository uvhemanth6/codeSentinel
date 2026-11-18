export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Confidence = 'high' | 'medium' | 'low'
export type Verification = 'static-match' | 'potential-risk' | 'heuristic'
export type Category = 'Security' | 'Code Slop' | 'Coding Gaps' | 'Loose Ends'

export interface Finding {
  id: string
  rule_id: string
  title: string
  category: Category
  subcategory: string
  severity: Severity
  file: string
  line: number | null
  end_line: number | null
  evidence: string
  explanation: string
  impact: string
  remediation: string
  confidence: Confidence
  source: string
  detected_by: string[]
  verification: Verification
  family: string
  language: string | null
  cwe: string | null
  context: { line: number; text: string }[]
  occurrences: { file?: string; line: number; snippet: string }[]
  tags: string[]
  dimension: string
  priority: number
  review: { reviewed: boolean; note: string }
}

export interface Dimension {
  label: string
  score: number | null
  grade: string
  findings: number
  points: number
  by_severity: Record<Severity, number>
  norm: number
  denominator: number
  explanation: string
}

export interface Scores {
  overall: number | null
  grade: string
  dimensions: Record<'security' | 'quality' | 'completeness' | 'maintainability', Dimension>
  slop: { score: number | null; findings: number; points: number; density_per_100_lines: number; explanation: string }
  weights: Record<string, number>
  counts: { total: number } & Record<Severity, number>
  code_lines: number
  method: string
}

export interface LanguageStat { language: string; files: number; lines: number; support: string; kind: string }

export interface Stage { key: string; label: string; status: 'pending' | 'running' | 'done' | 'failed'; detail: string; started: number | null; ended: number | null }

export interface RemediationItem {
  order: number; family: string; title: string; severity: Severity; category: string; count: number
  finding_ids: string[]; action: string; effort: string
}

export interface DeterministicReview {
  mode: 'deterministic'
  executive_summary: string
  top_risks: { finding_id: string; title: string; severity: Severity; file: string; line: number | null; why: string }[]
  architectural_risks: { title: string; description: string; evidence: string; finding_ids: string[] }[]
  remediation_plan: RemediationItem[]
  related_issue_groups: { label: string; reason: string; finding_ids: string[] }[]
}

export interface GeminiReview {
  mode: 'gemini' | 'deterministic'
  model?: string
  fallback_reason: string | null
  message?: string
  disclaimer?: string
  sent_findings?: number
  verified?: boolean
  deterministic: DeterministicReview
  review?: {
    executive_summary: string
    architectural_risks: { title: string; description: string; finding_ids: string[] }[]
    prioritized_remediation: { finding_id: string; priority: number; rationale: string; file: string; line: number | null; title: string; severity: Severity }[]
    finding_reviews: {
      finding_id: string; technical_implication: string; likely_false_positive: boolean; false_positive_reason: string
      suggested_fix_code: string; related_finding_ids: string[]; file: string; line: number | null; title: string; severity: Severity
    }[]
  }
}

export interface ScanResult {
  meta: Record<string, any>
  summary: { files_scanned: number; files_skipped: number; total_lines: number; code_lines: number; scores: Scores; duplicates_merged: number }
  languages: { languages: LanguageStat[]; unsupported: { extension: string; files: number }[] }
  structure: { top_level: { path: string; files: number }[]; max_depth: number; has_tests: boolean; has_readme: boolean; manifests: string[]; entry_points: string[]; frameworks: string[] }
  tools: Record<string, { status: string; reason?: string; findings?: number }>
  analyzers: { name: string; stage: string; status: string; findings: number; error: string | null }[]
  skipped: { counts: Record<string, number>; sample: { file: string; reason: string }[] }
  ai: { deterministic: DeterministicReview; gemini: GeminiReview | null; last_attempt?: { mode: string; fallback_reason: string | null; message: string | null; at: number } }
  settings: any
  ingestion: Record<string, any>
  finding_count: number
  file_count: number
}

export interface Scan {
  id: string
  name: string
  source_type: 'zip' | 'github' | 'sample'
  source_ref: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  stage: string
  error: string | null
  created_at: number
  finished_at: number | null
  stages: Stage[]
  options: { ai_consent?: boolean }
  summary: { files_scanned: number; code_lines: number; scores: Scores; frameworks: string[]; languages: LanguageStat[] } | null
  result?: ScanResult | null
}

export interface FindingsPage {
  total: number
  items: Finding[]
  facets: { severity: Record<string, number>; subcategory: Record<string, number>; source: Record<string, number>; verification: Record<string, number> }
  offset: number
  limit: number
  reviewed_total: number
  base_total: number
}

export interface FileRow { path: string; language: string; lines: number; bytes: number; support: string; findings: number }

export interface Health {
  status: string
  python: string
  tools: { bandit: boolean; semgrep: boolean; gemini: { configured: boolean; model: string; sdk: string; timeout_seconds: number } }
  limits: { max_upload_mb: number; max_files: number; max_uncompressed_mb: number }
  engine: { analyzers: { name: string; stage: string }[]; security_rules: number }
  languages: { name: string; support: string; extensions: string[] }[]
  samples: { id: string; label: string }[]
}

export interface Dashboard {
  latest: null | {
    scan_id: string; name: string; created_at: number; scores: Scores; languages: LanguageStat[]; frameworks: string[]
    files_scanned: number; code_lines: number; by_category: Record<string, number>
  }
  recent: Scan[]
  total_scans: number
  completed_scans: number
}

export interface Settings {
  weights: Record<string, number>
  severity_points: Record<string, number>
  confidence_factor: Record<string, number>
  norms: Record<string, number>
  size_factor: number
  thresholds: Record<string, number>
}

export interface AiPreview {
  payload: { project: any; findings: { id: string; title: string; severity: Severity; file: string; line: number | null; snippet: string }[] }
  ai: { configured: boolean; model: string }
  disclosure: string
}
