/**
 * src/test/components.test.tsx — Vitest unit tests with proper ESM imports.
 * Run: npm test -- --run
 */
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import React from 'react'
import { useStore } from '../store'
import { Badge, HndlBar, StatCard, Spinner, Card, Empty } from '../components/shared'
import { ErrorBoundary, SkeletonText, SkeletonCard, SkeletonTable, SkeletonScanList } from '../components/shared/ErrorBoundary'
import { api } from '../lib/api'

// ── Store ─────────────────────────────────────────────────────────────────────
describe('Zustand store', () => {
  beforeEach(() => useStore.getState().reset())

  it('starts empty', () => expect(useStore.getState().scans).toHaveLength(0))

  it('adds a scan', () => {
    useStore.getState().addScan({ scan_id: 'abc', target: 'x', target_type: 'repo', status: 'queued', hndl_score: 0, risk_level: '', finding_count: 0 })
    expect(useStore.getState().scans).toHaveLength(1)
  })

  it('deduplicates by scan_id, keeping latest', () => {
    const base = { scan_id: 'dup', target: 'x', target_type: 'repo' as const, status: 'queued' as const, hndl_score: 0, risk_level: '', finding_count: 0 }
    useStore.getState().addScan(base)
    useStore.getState().addScan({ ...base, status: 'complete' as const })
    expect(useStore.getState().scans).toHaveLength(1)
    expect(useStore.getState().scans[0].status).toBe('complete')
  })

  it('updates scan by id', () => {
    useStore.getState().addScan({ scan_id: 'u', target: 'y', target_type: 'repo', status: 'queued', hndl_score: 0, risk_level: '', finding_count: 0 })
    useStore.getState().updateScan('u', { hndl_score: 7.5 })
    expect(useStore.getState().scans[0].hndl_score).toBe(7.5)
  })

  it('caps log at 200 lines', () => {
    for (let i = 0; i < 250; i++)
      useStore.getState().addLogLine({ time: '0', level: 'info', message: `m${i}` })
    expect(useStore.getState().logLines.length).toBeLessThanOrEqual(200)
  })

  it('clears log', () => {
    useStore.getState().addLogLine({ time: '0', level: 'ok', message: 'hi' })
    useStore.getState().clearLog()
    expect(useStore.getState().logLines).toHaveLength(0)
  })

  it('sets page', () => {
    useStore.getState().setCurrentPage('eval')
    expect(useStore.getState().currentPage).toBe('eval')
  })

  it('reset restores defaults', () => {
    useStore.getState().setCurrentPage('heatmap')
    useStore.getState().reset()
    expect(useStore.getState().currentPage).toBe('scan')
    expect(useStore.getState().scans).toHaveLength(0)
  })
})

// ── Badge ─────────────────────────────────────────────────────────────────────
describe('Badge', () => {
  it('renders text', () => {
    render(<Badge variant="critical">Critical</Badge>)
    expect(screen.getByText('Critical')).toBeTruthy()
  })
  it('shows pulse dot', () => {
    const { container } = render(<Badge variant="scanning" pulse>scan</Badge>)
    expect(container.querySelector('.animate-pulse')).toBeTruthy()
  })
  it('no pulse by default', () => {
    const { container } = render(<Badge variant="complete">done</Badge>)
    expect(container.querySelector('.animate-pulse')).toBeNull()
  })
})

// ── HndlBar ───────────────────────────────────────────────────────────────────
describe('HndlBar', () => {
  it('shows label', () => { render(<HndlBar score={7.5} />); expect(screen.getByText('7.5')).toBeTruthy() })
  it('hides label', () => { render(<HndlBar score={7.5} showLabel={false} />); expect(screen.queryByText('7.5')).toBeNull() })
  it('renders 0', () => { render(<HndlBar score={0} />); expect(screen.getByText('0.0')).toBeTruthy() })
})

// ── StatCard ──────────────────────────────────────────────────────────────────
describe('StatCard', () => {
  it('renders num + label', () => {
    render(<StatCard num="8.5" label="HNDL" />)
    expect(screen.getByText('8.5')).toBeTruthy()
    expect(screen.getByText('HNDL')).toBeTruthy()
  })
})

// ── Spinner ───────────────────────────────────────────────────────────────────
describe('Spinner', () => {
  it('renders at default 18px', () => {
    const { container } = render(<Spinner />)
    expect((container.firstChild as HTMLElement).style.width).toBe('18px')
  })
  it('renders at custom size', () => {
    const { container } = render(<Spinner size={32} />)
    expect((container.firstChild as HTMLElement).style.width).toBe('32px')
  })
})

// ── ErrorBoundary ─────────────────────────────────────────────────────────────
const Bomb = ({ throws }: { throws: boolean }) => {
  if (throws) throw new Error('boom')
  return <div>safe</div>
}

describe('ErrorBoundary', () => {
  beforeEach(() => vi.spyOn(console, 'error').mockImplementation(() => {}))

  it('renders children when no error', () => {
    render(<ErrorBoundary><Bomb throws={false} /></ErrorBoundary>)
    expect(screen.getByText('safe')).toBeTruthy()
  })

  it('shows default fallback on error', () => {
    render(<ErrorBoundary><Bomb throws={true} /></ErrorBoundary>)
    expect(screen.getByText('Something went wrong')).toBeTruthy()
    expect(screen.getByText('boom')).toBeTruthy()
  })

  it('shows Try again button', () => {
    render(<ErrorBoundary><Bomb throws={true} /></ErrorBoundary>)
    expect(screen.getByText('Try again')).toBeTruthy()
  })

  it('uses custom fallback', () => {
    render(<ErrorBoundary fallback={e => <div>Err: {e.message}</div>}><Bomb throws={true} /></ErrorBoundary>)
    expect(screen.getByText('Err: boom')).toBeTruthy()
  })
})

// ── Skeletons ─────────────────────────────────────────────────────────────────
describe('Skeletons', () => {
  it('SkeletonText renders N pulse lines', () => {
    const { container } = render(<SkeletonText lines={4} />)
    expect(container.querySelectorAll('.animate-pulse').length).toBe(4)
  })
  it('SkeletonCard renders', () => {
    const { container } = render(<SkeletonCard />)
    expect(container.firstChild).toBeTruthy()
  })
  it('SkeletonTable renders rows×cols', () => {
    const { container } = render(<SkeletonTable rows={3} cols={4} />)
    expect(container.querySelectorAll('td').length).toBe(12)
  })
  it('SkeletonScanList renders 4 items', () => {
    const { container } = render(<SkeletonScanList />)
    expect(container.querySelectorAll('.border-b').length).toBe(4)
  })
})

// ── API client ────────────────────────────────────────────────────────────────
describe('API client', () => {
  it('has baseURL', () => expect(api.defaults.baseURL).toBeTruthy())
  it('has X-API-Key header', () => expect(api.defaults.headers['X-API-Key']).toBeTruthy())
  it('baseURL is localhost in tests', () => expect(api.defaults.baseURL).toContain('localhost'))
})
