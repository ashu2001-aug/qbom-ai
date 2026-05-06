/**
 * components/findings/FindingsPanel.tsx — Findings table with HNDL, compliance, BOM download.
 */
import React, { useState } from 'react'
import { useScans, useFindings, useHndlBreakdown, useCompliance, scanApi } from '@/lib/api'
import { Card, CardTitle, StatCard, Badge, HndlBar, Table, Tr, Td, Empty, Tabs, PageHeader, Spinner } from '@/components/shared'
import { SkeletonStatRow, SkeletonTable } from '@/components/shared/ErrorBoundary'

export function FindingsPanel() {
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)
  const [activeTab, setActiveTab]           = useState('Findings')
  const [downloading, setDownloading]       = useState(false)

  const { data: scansData } = useScans()
  const { data: findingsData, isLoading: loadingFindings } = useFindings(selectedScanId)
  const { data: hndlData } = useHndlBreakdown(selectedScanId)
  const { data: complianceData } = useCompliance(selectedScanId)

  const findings = findingsData?.findings || []
  const completed = scansData?.scans?.filter((s: any) => s.status === 'complete') || []

  const vulnCount   = findings.filter((f: any) => f.quantum_vulnerable).length
  const shadowCount = findings.filter((f: any) => f.is_shadow_crypto).length
  const avgHndl     = findings.length
    ? findings.reduce((a: number, f: any) => a + (f.hndl_score || 0), 0) / findings.length
    : 0

  const downloadBom = async () => {
    if (!selectedScanId) return
    setDownloading(true)
    try {
      const bom = await scanApi.getBom(selectedScanId)
      const blob = new Blob([JSON.stringify(bom, null, 2)], { type: 'application/json' })
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `qbom-${selectedScanId.slice(0, 8)}.cdx.json`
      a.click()
      URL.revokeObjectURL(url)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <div>
      <PageHeader
        title="Cryptographic Findings"
        sub="Select a completed scan to explore its quantum vulnerability inventory"
      />

      {/* Scan selector */}
      <Card className="mb-5">
        <CardTitle>Select scan</CardTitle>
        <select
          value={selectedScanId || ''}
          onChange={e => setSelectedScanId(e.target.value || null)}
          className="w-full bg-[#151922] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none"
        >
          <option value="">— choose a completed scan —</option>
          {completed.map((s: any) => (
            <option key={s.scan_id} value={s.scan_id}>
              {s.target} ({s.risk_level?.toUpperCase()} · HNDL {(s.hndl_score || 0).toFixed(1)})
            </option>
          ))}
        </select>
      </Card>

      {selectedScanId && (
        <>
          {/* Stats row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5 mb-5">
            <StatCard num={vulnCount}         label="Quantum vulnerable" color="danger" />
            <StatCard num={shadowCount}        label="Shadow crypto"      color="warn" />
            <StatCard num={findings.length}    label="Total findings"     color="info" />
            <StatCard num={avgHndl.toFixed(1)} label="Avg HNDL score"     color="accent" />
          </div>

          {/* Download BOM */}
          <div className="flex justify-end mb-3">
            <button
              onClick={downloadBom}
              disabled={downloading}
              className="flex items-center gap-2 text-xs border border-white/10 rounded-lg px-3.5 py-2 text-[#6b7280] hover:text-[#00e5a0] hover:border-[#00e5a0] transition-colors"
            >
              {downloading ? <Spinner size={12} /> : '↓'} CycloneDX v1.7 BOM
            </button>
          </div>

          {/* Tabs */}
          <Tabs
            tabs={['Findings', 'HNDL Breakdown', 'Compliance']}
            active={activeTab}
            onChange={setActiveTab}
          />

          {/* ── Findings tab ── */}
          {activeTab === 'Findings' && (
            <Card>
              <CardTitle>Algorithm inventory</CardTitle>
              {loadingFindings ? (
                <div className="space-y-4 py-2">
                  <SkeletonStatRow count={4} />
                  <SkeletonTable rows={5} cols={6} />
                </div>
              ) : (
                <Table headers={['Algorithm', 'Location', 'HNDL', 'Quantum?', 'Shadow?', 'Migration']}>
                  {!findings.length ? (
                    <tr><td colSpan={6}><Empty message="No findings" /></td></tr>
                  ) : findings
                      .slice()
                      .sort((a: any, b: any) => (b.hndl_score || 0) - (a.hndl_score || 0))
                      .map((f: any, i: number) => (
                    <Tr key={i}>
                      <Td>
                        <span className={f.quantum_vulnerable ? 'text-[#ff4d6d] font-semibold' : 'text-[#00e5a0] font-semibold'}>
                          {f.algorithm}
                        </span>
                      </Td>
                      <Td mono muted maxW="w-52">{f.location}</Td>
                      <Td><HndlBar score={f.hndl_score || 0} /></Td>
                      <Td>
                        <Badge variant={f.quantum_vulnerable ? 'critical' : 'low'}>
                          {f.quantum_vulnerable ? '⚠ Yes' : '✓ No'}
                        </Badge>
                      </Td>
                      <Td>
                        <Badge variant={f.is_shadow_crypto ? 'warn' : 'low'}>
                          {f.is_shadow_crypto ? 'Shadow' : 'Standard'}
                        </Badge>
                      </Td>
                      <Td muted maxW="w-44">{f.migration_path || '—'}</Td>
                    </Tr>
                  ))}
                </Table>
              )}
            </Card>
          )}

          {/* ── HNDL Breakdown tab ── */}
          {activeTab === 'HNDL Breakdown' && hndlData && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <StatCard num={hndlData.aggregate.max.toFixed(1)} label="Max HNDL"     color="danger" />
                <StatCard num={hndlData.aggregate.avg.toFixed(1)} label="Avg HNDL"     color="warn" />
                <StatCard num={hndlData.aggregate.critical_count} label="Critical (≥8)" color="danger" />
                <StatCard num={hndlData.aggregate.high_count}     label="High (6–8)"   color="warn" />
              </div>
              <Card>
                <CardTitle>Per-algorithm HNDL breakdown</CardTitle>
                <Table headers={['Algorithm', 'Location', 'HNDL Score', 'Risk Band', 'Migration']}>
                  {hndlData.breakdown.map((b: any, i: number) => (
                    <Tr key={i}>
                      <Td><span className="font-semibold">{b.algorithm}</span></Td>
                      <Td mono muted maxW="w-48">{b.location}</Td>
                      <Td><HndlBar score={b.hndl_score} /></Td>
                      <Td><Badge variant={b.risk_band as any}>{b.risk_band}</Badge></Td>
                      <Td muted maxW="w-44">{b.migration || '—'}</Td>
                    </Tr>
                  ))}
                </Table>
              </Card>
            </div>
          )}

          {/* ── Compliance tab ── */}
          {activeTab === 'Compliance' && complianceData && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3.5">
                <StatCard num={complianceData.summary.overdue}   label="Overdue"  color="danger" />
                <StatCard num={complianceData.summary.urgent}    label="Urgent"   color="warn" />
                <StatCard num={complianceData.summary.planned}   label="Planned"  color="info" />
                <StatCard num={complianceData.summary.compliant} label="Compliant" color="accent" />
              </div>
              <Card>
                <CardTitle>CNSA 2.0 compliance status</CardTitle>
                <Table headers={['Algorithm', 'Location', 'Deadline', 'Years Left', 'Replacement', 'Status']}>
                  {complianceData.items.map((item: any, i: number) => (
                    <Tr key={i}>
                      <Td><span className="font-semibold">{item.algorithm}</span></Td>
                      <Td mono muted maxW="w-40">{item.location}</Td>
                      <Td muted>{item.cnsa2_deadline}</Td>
                      <Td>
                        <span className={item.years_remaining <= 0 ? 'text-[#ff4d6d]' : item.years_remaining <= 2 ? 'text-amber-400' : 'text-[#6b7280]'}>
                          {item.years_remaining <= 0 ? 'OVERDUE' : `${item.years_remaining}y`}
                        </span>
                      </Td>
                      <Td muted maxW="w-44">{item.replacement}</Td>
                      <Td>
                        <Badge variant={item.status === 'overdue' ? 'critical' : item.status === 'urgent' ? 'warn' : 'info'}>
                          {item.status}
                        </Badge>
                      </Td>
                    </Tr>
                  ))}
                </Table>
              </Card>
            </div>
          )}
        </>
      )}
    </div>
  )
}
