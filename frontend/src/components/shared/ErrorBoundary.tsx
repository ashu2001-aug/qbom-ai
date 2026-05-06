/**
 * components/shared/ErrorBoundary.tsx — React error boundary for graceful crash handling.
 * components/shared/Skeleton.tsx      — Loading skeleton components.
 */
import React, { Component, type ReactNode } from 'react'

// ── Error Boundary ─────────────────────────────────────────────────────────────
interface ErrorBoundaryProps {
  children: ReactNode
  fallback?: (error: Error, reset: () => void) => ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[Q-BOM ErrorBoundary]', error, info.componentStack)
  }

  reset = () => this.setState({ error: null })

  render() {
    const { error } = this.state
    if (!error) return this.props.children

    if (this.props.fallback) {
      return this.props.fallback(error, this.reset)
    }

    return (
      <div className="flex items-center justify-center min-h-[200px] p-8">
        <div className="text-center max-w-md">
          <div className="text-[#ff4d6d] text-2xl mb-3">⚠</div>
          <div className="font-head text-base font-semibold mb-2">Something went wrong</div>
          <div className="text-[11px] text-[#6b7280] font-mono bg-[#151922] rounded-lg p-3 mb-4 text-left overflow-auto max-h-32">
            {error.message}
          </div>
          <button
            onClick={this.reset}
            className="text-xs bg-[#00e5a0] text-black px-4 py-2 rounded-lg font-semibold"
          >
            Try again
          </button>
        </div>
      </div>
    )
  }
}

// ── Skeleton loaders ───────────────────────────────────────────────────────────
interface SkeletonProps {
  className?: string
  width?: string
  height?: string
}

function Pulse({ className = '' }: { className?: string }) {
  return (
    <div className={`bg-[#151922] rounded animate-pulse ${className}`} />
  )
}

export function SkeletonText({ lines = 3, className = '' }: { lines?: number; className?: string }) {
  return (
    <div className={`space-y-2 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <Pulse
          key={i}
          className={`h-3 rounded ${i === lines - 1 ? 'w-3/4' : 'w-full'}`}
        />
      ))}
    </div>
  )
}

export function SkeletonCard({ className = '' }: { className?: string }) {
  return (
    <div className={`bg-[#0e1118] border border-white/[0.07] rounded-xl p-5 ${className}`}>
      <Pulse className="h-3 w-24 mb-4" />
      <SkeletonText lines={3} />
    </div>
  )
}

export function SkeletonTable({ rows = 5, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse">
        <thead>
          <tr>
            {Array.from({ length: cols }).map((_, i) => (
              <th key={i} className="px-3.5 py-2.5 border-b border-white/[0.07]">
                <Pulse className="h-2.5 w-16" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, r) => (
            <tr key={r} className="border-b border-white/[0.04]">
              {Array.from({ length: cols }).map((_, c) => (
                <td key={c} className="px-3.5 py-3">
                  <Pulse className={`h-2.5 ${c === 0 ? 'w-24' : c === cols - 1 ? 'w-16' : 'w-full max-w-[120px]'}`} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function SkeletonStatRow({ count = 4 }: { count?: number }) {
  return (
    <div className={`grid grid-cols-${count} gap-3.5`}>
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="bg-[#0e1118] border border-white/[0.07] rounded-xl p-5">
          <Pulse className="h-8 w-16 mb-2" />
          <Pulse className="h-2.5 w-24" />
        </div>
      ))}
    </div>
  )
}

export function SkeletonScanList() {
  return (
    <div className="space-y-0">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="flex items-center gap-4 px-3.5 py-3 border-b border-white/[0.07]">
          <Pulse className="h-3 flex-1 max-w-[200px]" />
          <Pulse className="h-5 w-16 rounded-full" />
          <Pulse className="h-5 w-20 rounded-full" />
          <Pulse className="h-5 w-14 rounded-full" />
          <div className="flex-1"><Pulse className="h-1.5 w-full max-w-[120px] rounded-full" /></div>
          <Pulse className="h-6 w-10" />
        </div>
      ))}
    </div>
  )
}
