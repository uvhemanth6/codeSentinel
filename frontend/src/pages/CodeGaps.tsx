import FindingsExplorer from '../components/FindingsExplorer'
import { Notice } from '../components/ui'
import { useScanCtx } from './ScanResults'

export default function CodeGaps() {
  const { scan } = useScanCtx()
  return (
    <div className="space-y-4">
      <Notice>Coding gaps and loose ends: unfinished implementations, TODO/FIXME markers, swallowed errors, missing validation, debugging leftovers and development-only configuration. Abstract methods, interfaces and documented no-ops are not flagged.</Notice>
      <FindingsExplorer scanId={scan.id} categories={['Coding Gaps', 'Loose Ends']} aiReview={scan.result?.ai.gemini}
        emptyMessage="No gaps or loose ends were detected." />
    </div>
  )
}
