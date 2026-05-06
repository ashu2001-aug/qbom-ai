/**
 * store/index.ts — Zustand global store.
 * Manages: active scans, findings, selected scan, WS connection, UI state.
 */
import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'

export interface Finding {
  algorithm: string
  location: string
  hndl_score: number
  quantum_vulnerable: boolean
  is_shadow_crypto: boolean
  migration_path?: string
  snippet?: string
  source?: string
  platform?: string
}

export interface Scan {
  scan_id: string
  target: string
  target_type: string
  status: 'queued' | 'scanning' | 'complete' | 'failed'
  hndl_score: number
  risk_level: string
  finding_count: number
  agent_trace?: {
    reflection_iterations: number
    reflection_passed: boolean
    message_count: number
  }
  created_at?: string
}

export interface LogLine {
  time: string
  level: 'info' | 'ok' | 'warn' | 'error'
  message: string
}

interface QBOMStore {
  // ── Scans ──────────────────────────────────────────────────────────────────
  scans: Scan[]
  activeScanId: string | null
  findings: Finding[]
  logLines: LogLine[]

  // ── UI ─────────────────────────────────────────────────────────────────────
  currentPage: string
  isScanRunning: boolean

  // ── Eval ───────────────────────────────────────────────────────────────────
  evalScores: {
    answerRelevancy: number
    faithfulness: number
    hallucination: number
    passRate: number
  } | null

  // ── Actions ────────────────────────────────────────────────────────────────
  setCurrentPage: (page: string) => void
  addScan: (scan: Scan) => void
  updateScan: (scanId: string, patch: Partial<Scan>) => void
  setActiveScan: (scanId: string) => void
  setFindings: (findings: Finding[]) => void
  addLogLine: (line: LogLine) => void
  clearLog: () => void
  setIsScanRunning: (v: boolean) => void
  setEvalScores: (scores: QBOMStore['evalScores']) => void
  reset: () => void
}

const initialState = {
  scans: [] as Scan[],
  activeScanId: null,
  findings: [] as Finding[],
  logLines: [] as LogLine[],
  currentPage: 'scan',
  isScanRunning: false,
  evalScores: null,
}

export const useStore = create<QBOMStore>()(
  devtools(
    persist(
      (set, get) => ({
        ...initialState,

        setCurrentPage: (page) => set({ currentPage: page }),

        addScan: (scan) =>
          set((s) => ({ scans: [scan, ...s.scans.filter(x => x.scan_id !== scan.scan_id)] })),

        updateScan: (scanId, patch) =>
          set((s) => ({
            scans: s.scans.map(sc => sc.scan_id === scanId ? { ...sc, ...patch } : sc)
          })),

        setActiveScan: (scanId) => set({ activeScanId: scanId }),

        setFindings: (findings) => set({ findings }),

        addLogLine: (line) =>
          set((s) => ({
            logLines: [...s.logLines.slice(-199), line]  // keep last 200
          })),

        clearLog: () => set({ logLines: [] }),

        setIsScanRunning: (v) => set({ isScanRunning: v }),

        setEvalScores: (scores) => set({ evalScores: scores }),

        reset: () => set(initialState),
      }),
      {
        name: 'qbom-store',
        partialize: (s) => ({ scans: s.scans.slice(0, 50) }), // persist only scan history
      }
    )
  )
)
