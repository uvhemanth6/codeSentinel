import FindingsExplorer from '../components/FindingsExplorer'
import { Notice } from '../components/ui'
import { useScanCtx } from './ScanResults'

const CATS = ['Security']

export default function SecurityFindings() {
  const { scan } = useScanCtx()
  return (
    <div className="space-y-4">
      <Notice>
        Findings marked <b>Static match</b> are deterministic detections of a known-bad construct; <b>Potential risk</b> means the pattern is suspicious but exploitability depends on data flow — confirm before acting.
      </Notice>
      <FindingsExplorer scanId={scan.id} categories={CATS} aiReview={scan.result?.ai.gemini}
        emptyMessage="No security issues were detected by the rules that apply to this project. This is not proof of security — see the scoring notes." />
    </div>
  )
}
