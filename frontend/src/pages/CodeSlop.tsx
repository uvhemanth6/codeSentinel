import { ScoreRing, Notice } from '../components/ui'
import FindingsExplorer from '../components/FindingsExplorer'
import { useScanCtx } from './ScanResults'

export default function CodeSlop() {
  const { scan } = useScanCtx()
  const slop = scan.result!.summary.scores.slop
  return (
    <div className="space-y-4">
      <div className="card-pad flex flex-wrap items-center gap-6">
        <ScoreRing score={slop.score} label="Code slop score" invert sub="↓ better" />
        <div className="min-w-[260px] flex-1 space-y-2 text-sm text-slate-300">
          <p>{slop.explanation}</p>
          <p className="text-xs text-slate-400">{slop.findings} findings · {slop.points} weighted points · {slop.density_per_100_lines} points per 100 lines</p>
        </div>
      </div>
      <Notice>CodeSentinel measures concrete low-quality patterns (duplication, complexity, dead code, naming…). It does <b>not</b> claim to detect whether code was AI-generated.</Notice>
      <FindingsExplorer scanId={scan.id} categories={['Code Slop']} aiReview={scan.result?.ai.gemini}
        emptyMessage="No measurable code-slop patterns were found." />
    </div>
  )
}
