import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../services/api'
import type { Scan } from '../types'

/** Loads a scan and polls while it is still running. */
export function useScan(id: string | undefined) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [error, setError] = useState<string | null>(null)
  const timer = useRef<number | undefined>(undefined)

  const load = useCallback(async () => {
    if (!id) return
    try {
      const s = await api.getScan(id)
      setScan(s)
      setError(null)
      if (s.status === 'queued' || s.status === 'running') {
        timer.current = window.setTimeout(load, 800)
      }
    } catch (e) {
      setError((e as Error).message)
    }
  }, [id])

  useEffect(() => {
    setScan(null)
    load()
    return () => window.clearTimeout(timer.current)
  }, [load])

  return { scan, error, reload: load, setScan }
}
