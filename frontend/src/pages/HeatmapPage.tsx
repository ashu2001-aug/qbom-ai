/**
 * pages/HeatmapPage.tsx — HNDL risk heatmap: Data Sensitivity × Algorithm.
 */
import React, { useState } from 'react'
import { Card, CardTitle, PageHeader } from '@/components/shared'
import clsx from 'clsx'

const ALGOS = ['RSA-2048', 'ECDSA-256', 'AES-128', 'SHA-1', 'MD5', 'DH-2048']
const SENS  = ['Public', 'Internal', 'Confidential', 'Medical', 'Financial']

// Pre-computed HNDL matrix [sensitivity][algorithm]
const MATRIX = [
  [1.0, 1.2, 0.8, 1.5, 2.0, 1.8],
  [3.0, 3.2, 2.0, 2.5, 4.0, 3.5],
  [5.5, 5.8, 3.5, 4.0, 6.0, 5.0],
  [8.5, 8.8, 5.0, 7.0, 9.0, 8.0],
  [9.5, 9.7, 6.0, 8.0, 9.5, 9.0],
]

function cellStyle(score: number) {
  if (score >= 8.5) return { bg: 'rgba(255,77,109,0.30)', color: '#ff4d6d' }
  if (score >= 6)   return { bg: 'rgba(255,77,109,0.12)', color: '#ff4d6d' }
  if (score >= 4)   return { bg: 'rgba(245,158,11,0.15)', color: '#f59e0b' }
  if (score >= 2)   return { bg: 'rgba(56,189,248,0.10)', color: '#38bdf8' }
  return { bg: 'rgba(0,229,160,0.08)', color: '#00e5a0' }
}

export function HeatmapPage() {
  const [hovered, setHovered] = useState<{ s: number; a: number } | null>(null)

  return (
    <div>
      <PageHeader
        title="HNDL Risk Heatmap"
        sub="Harvest-Now-Decrypt-Later risk matrix — data sensitivity × cryptographic algorithm"
      />

      <Card>
        <CardTitle>Risk matrix</CardTitle>
        <div className="overflow-x-auto">
          <table className="border-collapse">
            <thead>
              <tr>
                <th className="w-28 text-left text-[10px] uppercase tracking-wider text-[#6b7280] pb-2 pr-3 font-medium">
                  Sensitivity ↓
                </th>
                {ALGOS.map(a => (
                  <th key={a} className="text-center text-[10px] uppercase tracking-wider text-[#6b7280] pb-2 px-1.5 font-medium min-w-[88px]">
                    {a}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {SENS.map((s, si) => (
                <tr key={s}>
                  <td className="text-[11px] text-[#6b7280] pr-3 py-1 whitespace-nowrap">{s}</td>
                  {ALGOS.map((_, ai) => {
                    const score = MATRIX[si][ai]
                    const { bg, color } = cellStyle(score)
                    const isHovered = hovered?.s === si && hovered?.a === ai
                    return (
                      <td key={ai} className="p-1">
                        <div
                          className="flex items-center justify-center rounded-lg text-xs font-bold cursor-default transition-transform"
                          style={{
                            background: bg, color,
                            width: 80, height: 48,
                            transform: isHovered ? 'scale(1.1)' : 'scale(1)',
                            boxShadow: isHovered ? `0 0 12px ${color}40` : 'none',
                          }}
                          onMouseEnter={() => setHovered({ s: si, a: ai })}
                          onMouseLeave={() => setHovered(null)}
                          title={`${s} × ${ALGOS[ai]}: HNDL ${score.toFixed(1)}`}
                        >
                          {score.toFixed(1)}
                        </div>
                      </td>
                    )
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Tooltip */}
        {hovered && (
          <div className="mt-4 p-3 bg-[#151922] rounded-lg text-xs">
            <span className="font-semibold">{SENS[hovered.s]} × {ALGOS[hovered.a]}</span>
            <span className="text-[#6b7280] ml-2">
              HNDL score: <span style={{ color: cellStyle(MATRIX[hovered.s][hovered.a]).color }}>
                {MATRIX[hovered.s][hovered.a].toFixed(1)}
              </span>
            </span>
          </div>
        )}

        {/* Legend */}
        <div className="flex gap-5 mt-5 text-[11px]">
          <span className="text-[#6b7280]">Legend:</span>
          {[
            { label: '0–2 Minimal', color: '#00e5a0' },
            { label: '2–4 Low',     color: '#38bdf8' },
            { label: '4–6 Medium',  color: '#f59e0b' },
            { label: '6–8 High',    color: '#ff4d6d' },
            { label: '8–10 Critical',color:'#ff4d6d' },
          ].map(l => (
            <span key={l.label} style={{ color: l.color }}>● {l.label}</span>
          ))}
        </div>
      </Card>

      {/* HNDL explanation */}
      <Card className="mt-4">
        <CardTitle>About HNDL (Harvest Now, Decrypt Later)</CardTitle>
        <p className="text-xs text-[#6b7280] leading-relaxed max-w-2xl">
          Adversaries collect encrypted traffic today, storing it until a Cryptographically Relevant
          Quantum Computer (CRQC) is available — estimated 2030–2035. Data encrypted with
          quantum-vulnerable algorithms (RSA, ECDSA, etc.) that remains sensitive beyond that window
          is at risk <em>now</em>, even though quantum computers don't yet exist.
          The HNDL score combines algorithm vulnerability weight, data sensitivity, and
          exposure duration to quantify that present-day risk.
        </p>
      </Card>
    </div>
  )
}
