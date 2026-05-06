/**
 * pages/SimulatorPage.tsx — PQC Performance Cliff Simulator.
 * Also shows live HNDL score calculation via the /api/risk/score endpoint.
 */
import React, { useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { useHndlScore } from '@/lib/api'
import { Card, CardTitle, PageHeader, Spinner } from '@/components/shared'

const PQC_DATA: Record<string, { sizeRatio: number; keygenRatio: number; latencyMs: number; ciphertextBytes: number; notes: string }> = {
  'ML-KEM-768 (FIPS 203)': {
    sizeRatio: 32, keygenRatio: 3,  latencyMs: 18,
    ciphertextBytes: 1088,
    notes: 'Primary KEM for TLS. Replaces RSA/ECDH. Already in OpenSSL 3.5, BoringSSL.',
  },
  'ML-DSA-65 (FIPS 204)': {
    sizeRatio: 40, keygenRatio: 5, latencyMs: 22,
    ciphertextBytes: 3309,
    notes: 'Drop-in for ECDSA. Signature 3.3KB vs 72B. Good for TLS mTLS & code signing.',
  },
  'SLH-DSA-128s (FIPS 205)': {
    sizeRatio: 156, keygenRatio: 25, latencyMs: 90,
    ciphertextBytes: 7856,
    notes: 'Stateless hash-based. 7.8KB signatures. Best for firmware signing & PKI roots.',
  },
  'AES-256': {
    sizeRatio: 1, keygenRatio: 1, latencyMs: 0.5,
    ciphertextBytes: 32,
    notes: 'Drop-in for AES-128. 256-bit provides 128-bit quantum security (Grover). Low migration effort.',
  },
}

const CURRENT_ALGOS = ['RSA-2048', 'ECDSA-256', 'AES-128', 'DH-2048']
const SENS_OPTIONS  = ['low', 'medium', 'high', 'medical', 'financial', 'critical']

const TIMELINE = [
  { year: '2024', label: 'FIPS 203/204/205 published',    done: true },
  { year: '2025', label: 'ML-KEM in OpenSSL 3.5',          done: true },
  { year: '2026', label: 'CNSA 2.0 adoption begins',        done: false, now: true },
  { year: '2028', label: 'DH/DSA phase-out',                done: false },
  { year: '2030', label: 'RSA/ECDSA disallowed (NSS)',      done: false },
  { year: '2033', label: 'Full PQC mandate',                done: false },
]

export function SimulatorPage() {
  const [target, setTarget]   = useState('ML-KEM-768 (FIPS 203)')
  const [current, setCurrent] = useState('RSA-2048')
  const [sens, setSens]       = useState('medium')
  const [years, setYears]     = useState(10)

  const scoreCalc = useHndlScore()

  const pqc = PQC_DATA[target]

  const barData = [
    { name: 'Classical\nkey size', before: 256,  after: pqc.ciphertextBytes },
    { name: 'Latency (ms)',       before: 2,     after: pqc.latencyMs },
  ]

  return (
    <div>
      <PageHeader
        title="PQC Performance Cliff Simulator"
        sub="Estimate operational impact of migrating to post-quantum algorithms"
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        {/* ── Controls ── */}
        <Card>
          <CardTitle>Migration parameters</CardTitle>
          <div className="space-y-4">
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#6b7280] mb-1.5">Current algorithm</label>
              <select value={current} onChange={e => setCurrent(e.target.value)}
                className="w-full bg-[#151922] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none">
                {CURRENT_ALGOS.map(a => <option key={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#6b7280] mb-1.5">PQC replacement</label>
              <select value={target} onChange={e => setTarget(e.target.value)}
                className="w-full bg-[#151922] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none">
                {Object.keys(PQC_DATA).map(k => <option key={k}>{k}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#6b7280] mb-1.5">Data sensitivity</label>
              <select value={sens} onChange={e => setSens(e.target.value)}
                className="w-full bg-[#151922] border border-white/10 rounded-lg px-3 py-2.5 text-xs font-mono outline-none">
                {SENS_OPTIONS.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-[10px] uppercase tracking-wider text-[#6b7280] mb-1">
                Data lifetime: <span className="text-[#e8eaf0]">{years} years</span>
              </label>
              <input type="range" min={1} max={30} value={years} onChange={e => setYears(Number(e.target.value))} />
            </div>

            <button
              onClick={() => scoreCalc.mutate({ algo: current, sens, years })}
              disabled={scoreCalc.isPending}
              className="w-full flex items-center justify-center gap-2 bg-[#00e5a0] text-black py-2.5 rounded-lg text-xs font-semibold disabled:opacity-40"
            >
              {scoreCalc.isPending ? <Spinner size={14} /> : null} Calculate HNDL Score
            </button>

            {scoreCalc.data && (
              <div className="bg-[#151922] rounded-lg p-3 text-xs">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[#6b7280]">HNDL Risk Score</span>
                  <span className="font-head text-xl font-bold" style={{
                    color: scoreCalc.data.hndl_score >= 8 ? '#ff4d6d' :
                           scoreCalc.data.hndl_score >= 6 ? '#f59e0b' : '#00e5a0'
                  }}>
                    {scoreCalc.data.hndl_score.toFixed(1)} / 10
                  </span>
                </div>
                <div className="text-[#6b7280]">Risk band: <span className="text-[#e8eaf0]">{scoreCalc.data.risk_band}</span></div>
              </div>
            )}
          </div>
        </Card>

        {/* ── Impact stats ── */}
        <Card>
          <CardTitle>Migration impact</CardTitle>
          <div className="grid grid-cols-2 gap-3 mb-4">
            {[
              { label: 'Size increase',    value: `${pqc.sizeRatio}×`,      color: '#ff4d6d' },
              { label: 'Key gen overhead', value: `${pqc.keygenRatio}×`,    color: '#f59e0b' },
              { label: 'TLS latency',      value: `+${pqc.latencyMs}ms`,    color: '#38bdf8' },
              { label: 'Quantum secure',   value: '✓',                      color: '#00e5a0' },
            ].map(s => (
              <div key={s.label} className="bg-[#151922] rounded-lg p-3 text-center">
                <div className="font-head text-2xl font-bold" style={{ color: s.color }}>{s.value}</div>
                <div className="text-[11px] text-[#6b7280] mt-1">{s.label}</div>
              </div>
            ))}
          </div>
          <p className="text-[11px] text-[#6b7280] leading-relaxed mb-4">{pqc.notes}</p>

          {/* Size comparison chart */}
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={barData} margin={{ top: 0, right: 0, bottom: 0, left: -20 }}>
              <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
              <XAxis dataKey="name" tick={{ fill: '#6b7280', fontSize: 10 }} />
              <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
              <Tooltip
                contentStyle={{ background: '#0e1118', border: '1px solid rgba(255,255,255,0.07)', fontSize: 11 }}
                labelStyle={{ color: '#6b7280' }}
              />
              <Bar dataKey="before" name="Classical" fill="#38bdf8" radius={[3, 3, 0, 0]} />
              <Bar dataKey="after"  name="PQC"       fill="#00e5a0" radius={[3, 3, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* ── CNSA 2.0 timeline ── */}
      <Card>
        <CardTitle>CNSA 2.0 migration timeline</CardTitle>
        <div className="relative pt-2 pb-6">
          <div className="absolute top-[30px] left-0 right-0 h-px bg-white/[0.07]" />
          <div className="flex justify-between relative">
            {TIMELINE.map(t => (
              <div key={t.year} className="flex flex-col items-center text-center flex-1">
                <div className="relative mb-2">
                  <div
                    className="w-3 h-3 rounded-full border-2"
                    style={{
                      background: t.done ? '#00e5a0' : t.now ? '#38bdf8' : t.year <= '2028' ? '#f59e0b' : '#ff4d6d',
                      borderColor: 'var(--bg)',
                    }}
                  />
                  {t.now && (
                    <div className="absolute -top-0.5 -left-0.5 w-4 h-4 rounded-full border border-[#38bdf8] animate-ping opacity-50" />
                  )}
                </div>
                <div className="font-head text-sm font-bold" style={{
                  color: t.done ? '#00e5a0' : t.now ? '#38bdf8' : '#6b7280'
                }}>
                  {t.year}
                </div>
                <div className="text-[10px] text-[#6b7280] mt-1 max-w-[80px] leading-tight">{t.label}</div>
              </div>
            ))}
          </div>
        </div>
      </Card>
    </div>
  )
}
