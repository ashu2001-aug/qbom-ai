/**
 * App.tsx — Root component. Renders sidebar + current page.
 * Uses Zustand page state rather than React Router (single-page, no URL routing needed).
 */
import React from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Sidebar } from '@/components/shared/Sidebar'
import { ScanForm } from '@/components/scan/ScanForm'
import { FindingsPanel } from '@/components/findings/FindingsPanel'
import { AgentTrace } from '@/components/agents/AgentTrace'
import { EvalDashboard } from '@/components/eval/EvalDashboard'
import { HeatmapPage } from '@/pages/HeatmapPage'
import { SimulatorPage } from '@/pages/SimulatorPage'
import { ErrorBoundary } from '@/components/shared/ErrorBoundary'
import { useStore } from '@/store'
import { PageHeader } from '@/components/shared'

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, staleTime: 10_000 } },
})

function PageContent() {
  const { currentPage } = useStore()

  switch (currentPage) {
    case 'scan':      return <><PageHeader title="Quantum Vulnerability Scan" sub="Scan GitHub repos or live websites for quantum-vulnerable cryptographic primitives" /><ScanForm /></>
    case 'findings':  return <FindingsPanel />
    case 'heatmap':   return <HeatmapPage />
    case 'simulator': return <SimulatorPage />
    case 'agents':    return <AgentTrace />
    case 'eval':      return <EvalDashboard />
    default:          return <><PageHeader title="Not found" /><p className="text-[#6b7280]">Unknown page.</p></>
  }
}

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <div className="flex min-h-screen">
        <Sidebar />
        <main className="flex-1 px-8 py-8 max-w-5xl fade-in">
          <ErrorBoundary>
            <PageContent />
          </ErrorBoundary>
        </main>
      </div>
    </QueryClientProvider>
  )
}
