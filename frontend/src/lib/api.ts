/**
 * lib/api.ts — Axios client + React Query hooks for all Q-BOM API calls.
 */
import axios from 'axios'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

const API_KEY = import.meta.env.VITE_API_KEY || 'qbom-demo-key-2025'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: { 'X-API-Key': API_KEY },
})

// ── Types ──────────────────────────────────────────────────────────────────────
export interface ScanRequest {
  target: string
  target_type: 'repo' | 'website'
  data_sensitivity?: string
}

export interface ScanListItem {
  scan_id: string
  target: string
  target_type: string
  status: string
  hndl_score: number
  risk_level: string
  finding_count: number
  created_at: string
}

export interface Finding {
  algorithm: string
  location: string
  hndl_score: number
  quantum_vulnerable: boolean
  is_shadow_crypto: boolean
  migration_path?: string
  snippet?: string
}

export interface HndlBreakdown {
  scan_id: string
  target: string
  aggregate: {
    max: number
    avg: number
    critical_count: number
    high_count: number
    medium_count: number
    low_count: number
  }
  breakdown: Array<{
    algorithm: string
    location: string
    hndl_score: number
    risk_band: string
    quantum_vulnerable: boolean
    migration: string
  }>
}

export interface ComplianceResult {
  scan_id: string
  summary: { overdue: number; urgent: number; planned: number; compliant: number }
  overall_status: string
  items: Array<{
    algorithm: string
    location: string
    cnsa2_deadline: number
    years_remaining: number
    replacement: string
    fips_standard: string
    status: string
  }>
}

// ── Raw API functions ──────────────────────────────────────────────────────────
export const scanApi = {
  create:       (req: ScanRequest)   => api.post('/api/scan', req).then(r => r.data),
  get:          (id: string)         => api.get(`/api/scan/${id}`).then(r => r.data),
  list:         (page = 1, size = 20) => api.get('/api/scans', { params: { page, page_size: size } }).then(r => r.data),
  getFindings:  (id: string)         => api.get(`/api/scan/${id}/findings`).then(r => r.data),
  getBom:       (id: string)         => api.get(`/api/scan/${id}/bom`).then(r => r.data),
  getReport:    (id: string)         => api.get(`/api/scan/${id}/report`).then(r => r.data),
  delete:       (id: string)         => api.delete(`/api/scan/${id}`),
}

export const riskApi = {
  hndl:       (id: string)           => api.get(`/api/risk/${id}/hndl`).then(r => r.data),
  compliance: (id: string)           => api.get(`/api/risk/${id}/compliance`).then(r => r.data),
  project:    (name: string)         => api.get(`/api/risk/project/${name}`).then(r => r.data),
  score:      (algo: string, sens: string, years: number) =>
    api.post('/api/risk/score', { algorithm: algo, data_sensitivity: sens, exposure_years: years }).then(r => r.data),
}

export const knowledgeApi = {
  retrieve: (query: string, topK = 5) =>
    api.post('/api/knowledge/retrieve', { query, top_k: topK }).then(r => r.data),
  seed:     () => api.post('/api/knowledge/seed').then(r => r.data),
  list:     () => api.get('/api/knowledge/algorithms').then(r => r.data),
}

export const evalApi = {
  run: () => api.get('/api/eval/run').then(r => r.data),
}

// ── React Query hooks ──────────────────────────────────────────────────────────
export const useScans = (page = 1) =>
  useQuery({ queryKey: ['scans', page], queryFn: () => scanApi.list(page), refetchInterval: 5000 })

export const useScan = (id: string | null) =>
  useQuery({
    queryKey: ['scan', id],
    queryFn: () => scanApi.get(id!),
    enabled: !!id,
    refetchInterval: (q) => {
      const status = (q.state.data as any)?.status
      return status === 'complete' || status === 'failed' ? false : 3000
    },
  })

export const useFindings = (id: string | null) =>
  useQuery({
    queryKey: ['findings', id],
    queryFn: () => scanApi.getFindings(id!),
    enabled: !!id,
  })

export const useHndlBreakdown = (id: string | null) =>
  useQuery({
    queryKey: ['hndl', id],
    queryFn: () => riskApi.hndl(id!),
    enabled: !!id,
  })

export const useCompliance = (id: string | null) =>
  useQuery({
    queryKey: ['compliance', id],
    queryFn: () => riskApi.compliance(id!),
    enabled: !!id,
  })

export const useCreateScan = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: scanApi.create,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export const useDeleteScan = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: scanApi.delete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  })
}

export const useRetrieve = () =>
  useMutation({ mutationFn: ({ query, topK }: { query: string; topK?: number }) =>
    knowledgeApi.retrieve(query, topK) })

export const useRunEval = () =>
  useMutation({ mutationFn: evalApi.run })

export const useHndlScore = () =>
  useMutation({ mutationFn: ({ algo, sens, years }: { algo: string; sens: string; years: number }) =>
    riskApi.score(algo, sens, years) })
