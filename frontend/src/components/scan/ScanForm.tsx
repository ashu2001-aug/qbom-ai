/**
 * components/scan/ScanForm.tsx — Scan submission form with live agent log.
 *
 * - Submits to POST /api/scan
 * - Connects WebSocket immediately for real-time agent logs
 * - Falls back to polling if WS unavailable
 */
import React, { useState } from 'react'
import { useCreateScan, useScans } from '@/lib/api'
import { useStore } from '@/store'
import { useScanWebSocket } from '@/hooks/useWebSocket'
import { Badge, Card, CardTitle, HndlBar, Spinner, Table, Tr, Td, Empty } from '@/components/shared'
import { SkeletonScanList } from '@/components/shared/ErrorBoundary'
import clsx from 'clsx'

const SENSITIVITIES = ['low', 'medium', 'high', 'medical', 'financial', 'critical']

export function ScanForm() {
  const [target, setTarget]           = useState('')
  const [targetType, setTargetType]   = useState<'repo' | 'website'>('repo')
  const [sensitivity, setSensitivity] = useState('medium')
  const [activeScanId, setActiveScanId] = useState<string | null>(null)

  const createScan = useCreateScan()
  const { data: scansData, refetch: refetchScans } = useScans()
  const { logLines, addLogLine, clearLog, setFindings, updateScan, isScanRunning, setIsScanRunning } = useStore()

  // WebSocket live stream
  useScanWebSocket(activeScanId, {
    onComplete: (evt) => {
      setIsScanRunning(false)
      refetchScans()
    },
    onLog: () => {},
  })

  const handleScan = async () => {
    if (!target.trim() || isScanRunning) return
    clearLog()
    setIsScanRunning(true)

    addLogLine({ time: ts(), level: 'info', message: `Submitting scan for ${target}…` })

    try {
      const data = await createScan.mutateAsync({ target: target.trim(), target_type: targetType, data_sensitivity: sensitivity })
      setActiveScanId(data.scan_id)
      addLogLine({ time: ts(), level: 'ok', message: `Scan queued — ID: ${data.scan_id.slice(0, 8)}…` })
      addLogLine({ time: ts(), level: 'info', message: 'Connecting to agent stream…' })
    } catch (e: any) {
      addLogLine({ time: ts(), level: 'error', message: `Request failed: ${e.message}` })
      setIsScanRunning(false)
    }
  }

  return (
    <div>
      {/* ── Input form ── */}
      <div className="flex gap-2 mb-6 flex-wrap">
        <input
          value={target}
          onChange={e => setTarget(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="https://github.com/org/repo  or  https://example.com"
          className="flex-1 min-w-[280px] bg-[#0e1118] border border-white/10 rounded-lg px-3.5 py-2.5 text-xs font-mono outline-none focus:border-[#00e5a0] transition-colors"
        />
        <select
          value={targetType}
          onChange={e => setTargetType(e.target.value as 'repo' | 'website')}
          className="bg-[#0e1118] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none cursor-pointer"
        >
          <option value="repo">Repository</option>
          <option value="website">Website</option>
        </select>
        <select
          value={sensitivity}
          onChange={e => setSensitivity(e.target.value)}
          className="bg-[#0e1118] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none cursor-pointer"
        >
          {SENSITIVITIES.map(s => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)} sensitivity</option>
          ))}
        </select>
        <button
          onClick={handleScan}
          disabled={!target.trim() || isScanRunning}
          className="bg-[#00e5a0] text-black px-5 py-2.5 rounded-lg text-xs font-semibold font-mono disabled:opacity-40 disabled:cursor-not-allowed hover:brightness-110 transition-all flex items-center gap-2"
        >
          {isScanRunning ? <><Spinner size={14} /> Scanning…</> : '▶ Scan'}
        </button>
      </div>

      {/* ── Live agent log ── */}
      {logLines.length > 0 && (
        <Card className="mb-6">
          <div className="flex items-center gap-3 mb-4">
            {isScanRunning && <Spinner />}
            <div>
              <div className="font-semibold text-xs">{isScanRunning ? 'LangGraph agents running…' : 'Scan complete'}</div>
              <div className="text-[#6b7280] text-[11px]">{target}</div>
            </div>
            {isScanRunning && (
              <Badge variant="scanning" pulse>scanning</Badge>
            )}
          </div>
          <div className="log-container space-y-0.5">
            {logLines.map((line, i) => (
              <div key={i} className="flex gap-4 py-1 border-b border-white/[0.04] last:border-0">
                <span className="text-[#6b7280] text-[11px] min-w-[70px] shrink-0">{line.time}</span>
                <span className={clsx('text-xs', {
                  'text-sky-400': line.level === 'info',
                  'text-[#00e5a0]': line.level === 'ok',
                  'text-amber-400': line.level === 'warn',
                  'text-red-400': line.level === 'error',
                })}>
                  {line.message}
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* ── Recent scans table ── */}
      <Card>
        <CardTitle>Recent scans</CardTitle>
        <Table headers={['Target', 'Type', 'Status', 'Risk', 'HNDL', 'Findings', '']}>
          {!scansData ? (
            <tr><td colSpan={7}><SkeletonScanList /></td></tr>
          ) : !scansData?.scans?.length ? (
            <tr><td colSpan={7}><Empty message="No scans yet. Submit your first scan above." /></td></tr>
          ) : scansData.scans.map((scan: any) => (
            <Tr key={scan.scan_id}>
              <Td mono maxW="w-48">{scan.target}</Td>
              <Td><Badge variant={scan.target_type}>{scan.target_type}</Badge></Td>
              <Td>
                <Badge variant={scan.status} pulse={scan.status === 'scanning'}>
                  {scan.status}
                </Badge>
              </Td>
              <Td>
                {scan.risk_level && <Badge variant={scan.risk_level as any}>{scan.risk_level}</Badge>}
              </Td>
              <Td><HndlBar score={scan.hndl_score || 0} /></Td>
              <Td muted>{scan.finding_count || 0}</Td>
              <Td>
                <button
                  className="text-[11px] text-[#6b7280] border border-white/10 rounded px-2 py-1 hover:text-[#00e5a0] hover:border-[#00e5a0] transition-colors"
                  onClick={() => useStore.getState().setCurrentPage('findings')}
                >
                  View
                </button>
              </Td>
            </Tr>
          ))}
        </Table>
      </Card>
    </div>
  )
}

function ts() { return new Date().toLocaleTimeString('en', { hour12: false }) }
