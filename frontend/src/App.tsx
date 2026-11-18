import { Route, Routes } from 'react-router-dom'
import AppLayout from './layouts/AppLayout'
import AIReview from './pages/AIReview'
import CodeGaps from './pages/CodeGaps'
import CodeSlop from './pages/CodeSlop'
import Dashboard from './pages/Dashboard'
import FilesTab from './pages/FilesTab'
import History from './pages/History'
import Landing from './pages/Landing'
import NewScan from './pages/NewScan'
import NotFound from './pages/NotFound'
import ScanOverview from './pages/ScanOverview'
import ScanResults from './pages/ScanResults'
import SecurityFindings from './pages/SecurityFindings'
import SettingsPage from './pages/Settings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route element={<AppLayout />}>
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/history" element={<History />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="/scans/:id" element={<ScanResults />}>
          <Route index element={<ScanOverview />} />
          <Route path="security" element={<SecurityFindings />} />
          <Route path="slop" element={<CodeSlop />} />
          <Route path="gaps" element={<CodeGaps />} />
          <Route path="ai" element={<AIReview />} />
          <Route path="files" element={<FilesTab />} />
        </Route>
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  )
}
