/**
 * hooks/useWebSocket.ts — Real-time agent log streaming via WebSocket.
 *
 * Connects to /api/scan/{id}/stream immediately after scan creation.
 * Parses log events, completion events, and error events.
 */
import { useEffect, useRef, useCallback } from 'react'
import { useStore } from '@/store'

const WS_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000')
  .replace(/^http/, 'ws')

export type WsEvent =
  | { type: 'log'; level: 'info' | 'ok' | 'warn' | 'error'; message: string; scan_id: string }
  | { type: 'complete'; scan_id: string; finding_count: number; hndl_score: number; risk_level: string }
  | { type: 'pong' }

interface UseWebSocketOptions {
  onComplete?: (event: Extract<WsEvent, { type: 'complete' }>) => void
  onLog?: (event: Extract<WsEvent, { type: 'log' }>) => void
}

export function useScanWebSocket(scanId: string | null, opts: UseWebSocketOptions = {}) {
  const ws = useRef<WebSocket | null>(null)
  const { addLogLine, updateScan } = useStore()
  const pingInterval = useRef<ReturnType<typeof setInterval> | null>(null)

  const connect = useCallback((id: string) => {
    if (ws.current?.readyState === WebSocket.OPEN) return

    const url = `${WS_BASE}/api/scan/${id}/stream`
    const socket = new WebSocket(url)
    ws.current = socket

    socket.onopen = () => {
      addLogLine({ time: now(), level: 'info', message: 'Connected to agent stream…' })
      // Keep-alive ping every 30s
      pingInterval.current = setInterval(() => {
        if (socket.readyState === WebSocket.OPEN) socket.send('ping')
      }, 30_000)
    }

    socket.onmessage = (e) => {
      try {
        const event: WsEvent = JSON.parse(e.data)

        if (event.type === 'log') {
          addLogLine({ time: now(), level: event.level, message: event.message })
          opts.onLog?.(event)
        } else if (event.type === 'complete') {
          addLogLine({
            time: now(), level: 'ok',
            message: `✓ Scan complete — ${event.finding_count} findings, HNDL: ${event.hndl_score.toFixed(1)}, risk: ${event.risk_level}`
          })
          updateScan(id, {
            status: 'complete',
            hndl_score: event.hndl_score,
            risk_level: event.risk_level,
            finding_count: event.finding_count,
          })
          opts.onComplete?.(event)
          disconnect()
        }
      } catch (_) {}
    }

    socket.onerror = () => {
      addLogLine({ time: now(), level: 'warn', message: 'WebSocket unavailable — using polling fallback' })
    }

    socket.onclose = () => {
      if (pingInterval.current) clearInterval(pingInterval.current)
    }
  }, [])

  const disconnect = useCallback(() => {
    ws.current?.close()
    ws.current = null
    if (pingInterval.current) clearInterval(pingInterval.current)
  }, [])

  useEffect(() => {
    if (scanId) connect(scanId)
    return () => disconnect()
  }, [scanId])

  return { connect, disconnect }
}

function now(): string {
  return new Date().toLocaleTimeString('en', { hour12: false })
}
