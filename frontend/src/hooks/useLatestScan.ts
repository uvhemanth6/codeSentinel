import { useAsync } from './useAsync'
import { api } from '../services/api'

export function useLatestScanId(): string | null {
  const { data } = useAsync(() => api.dashboard(), [])
  return data?.latest?.scan_id ?? null
}
