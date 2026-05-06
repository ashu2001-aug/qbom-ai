/**
 * components/shared/index.tsx — Reusable UI primitives.
 */
import React from 'react'
import clsx from 'clsx'

// ── Badge ──────────────────────────────────────────────────────────────────────
type BadgeVariant = 'queued'|'scanning'|'complete'|'failed'|'critical'|'high'|'medium'|'low'|'minimal'|'info'|'warn'|'repo'|'website'

const BADGE_STYLES: Record<BadgeVariant, string> = {
  queued:   'bg-gray-500/10 text-gray-400',
  scanning: 'bg-sky-400/10 text-sky-400',
  complete: 'bg-emerald-400/10 text-emerald-400',
  failed:   'bg-red-400/10 text-red-400',
  critical: 'bg-red-400/15 text-red-400',
  high:     'bg-amber-400/15 text-amber-400',
  medium:   'bg-sky-400/10 text-sky-400',
  low:      'bg-emerald-400/10 text-emerald-400',
  minimal:  'bg-emerald-400/10 text-emerald-400',
  info:     'bg-sky-400/10 text-sky-400',
  warn:     'bg-amber-400/15 text-amber-400',
  repo:     'bg-violet-400/10 text-violet-400',
  website:  'bg-sky-400/10 text-sky-400',
}

export function Badge({ variant, children, pulse }: { variant: BadgeVariant; children: React.ReactNode; pulse?: boolean }) {
  return (
    <span className={clsx(
      'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider',
      BADGE_STYLES[variant] || BADGE_STYLES.info
    )}>
      {pulse && <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />}
      {children}
    </span>
  )
}

// ── Card ───────────────────────────────────────────────────────────────────────
export function Card({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={clsx('bg-[#0e1118] border border-white/[0.07] rounded-xl p-5', className)}>
      {children}
    </div>
  )
}

export function CardTitle({ children }: { children: React.ReactNode }) {
  return (
    <div className="font-head text-[11px] font-semibold uppercase tracking-widest text-[#6b7280] mb-4">
      {children}
    </div>
  )
}

// ── HNDL Progress Bar ──────────────────────────────────────────────────────────
export function HndlBar({ score, showLabel = true }: { score: number; showLabel?: boolean }) {
  const color =
    score >= 8 ? '#ff4d6d' :
    score >= 6 ? '#f59e0b' :
    score >= 4 ? '#38bdf8' : '#00e5a0'

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1 bg-[#151922] rounded-full overflow-hidden min-w-[80px]">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${score * 10}%`, background: color }}
        />
      </div>
      {showLabel && (
        <span className="text-[11px] tabular-nums min-w-[28px] text-right" style={{ color }}>
          {score.toFixed(1)}
        </span>
      )}
    </div>
  )
}

// ── Stat Card ──────────────────────────────────────────────────────────────────
type StatColor = 'accent' | 'danger' | 'warn' | 'info' | 'muted'
const STAT_COLOR: Record<StatColor, string> = {
  accent: 'text-[#00e5a0]', danger: 'text-[#ff4d6d]',
  warn: 'text-[#f59e0b]',   info: 'text-sky-400', muted: 'text-[#6b7280]',
}

export function StatCard({ num, label, color = 'accent' }: { num: string | number; label: string; color?: StatColor }) {
  return (
    <Card>
      <div className={clsx('font-head text-3xl font-bold leading-none', STAT_COLOR[color])}>{num}</div>
      <div className="text-[11px] text-[#6b7280] uppercase tracking-wider mt-1.5">{label}</div>
    </Card>
  )
}

// ── Spinner ────────────────────────────────────────────────────────────────────
export function Spinner({ size = 18 }: { size?: number }) {
  return (
    <span
      className="inline-block rounded-full border-2 border-white/10 border-t-[#00e5a0] animate-spin"
      style={{ width: size, height: size }}
    />
  )
}

// ── Table ──────────────────────────────────────────────────────────────────────
export function Table({ headers, children }: { headers: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr>
            {headers.map(h => (
              <th key={h} className="text-left px-3.5 py-2.5 text-[10px] uppercase tracking-wider text-[#6b7280] font-medium border-b border-white/[0.07]">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  )
}

export function Tr({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) {
  return (
    <tr
      className={clsx('border-b border-white/[0.07] last:border-0 hover:bg-white/[0.02] transition-colors', onClick && 'cursor-pointer')}
      onClick={onClick}
    >
      {children}
    </tr>
  )
}

export function Td({ children, mono, muted, maxW }: { children: React.ReactNode; mono?: boolean; muted?: boolean; maxW?: string }) {
  return (
    <td className={clsx('px-3.5 py-2.5 align-middle', mono && 'font-mono', muted && 'text-[#6b7280]', maxW && 'max-w-0')}>
      {maxW ? (
        <div className={clsx('truncate', maxW)}>{children}</div>
      ) : children}
    </td>
  )
}

// ── Empty state ────────────────────────────────────────────────────────────────
export function Empty({ message }: { message: string }) {
  return (
    <div className="py-12 text-center text-[#6b7280] text-xs">{message}</div>
  )
}

// ── Page header ────────────────────────────────────────────────────────────────
export function PageHeader({ title, sub }: { title: string; sub?: string }) {
  return (
    <div className="mb-7">
      <h1 className="font-head text-2xl font-bold tracking-tight">{title}</h1>
      {sub && <p className="text-[#6b7280] text-xs mt-1">{sub}</p>}
    </div>
  )
}

// ── Tabs ───────────────────────────────────────────────────────────────────────
export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: string; onChange: (t: string) => void }) {
  return (
    <div className="flex gap-0.5 mb-5 border-b border-white/[0.07]">
      {tabs.map(tab => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          className={clsx(
            'px-4 py-2 text-xs uppercase tracking-wider border-b-2 -mb-px transition-colors',
            active === tab
              ? 'text-[#00e5a0] border-[#00e5a0]'
              : 'text-[#6b7280] border-transparent hover:text-[#e8eaf0]'
          )}
        >
          {tab}
        </button>
      ))}
    </div>
  )
}
