/**
 * components/shared/Sidebar.tsx — Navigation sidebar.
 */
import React from 'react'
import { useStore } from '@/store'
import clsx from 'clsx'

const NAV = [
  { id: 'scan',      label: 'New Scan',      icon: '◎' },
  { id: 'findings',  label: 'Findings',       icon: '◈' },
  { id: 'heatmap',   label: 'Risk Heatmap',   icon: '◧' },
  { id: 'simulator', label: 'PQC Simulator',  icon: '◫' },
  { id: 'agents',    label: 'Agent Trace',    icon: '◎' },
  { id: 'eval',      label: 'Evaluation',     icon: '◉' },
]

export function Sidebar() {
  const { currentPage, setCurrentPage, isScanRunning } = useStore()

  return (
    <aside className="w-52 min-h-screen bg-[#0e1118] border-r border-white/[0.07] flex flex-col py-6 sticky top-0 h-screen">
      {/* Logo */}
      <div className="px-5 pb-7">
        <div className="font-head text-lg font-extrabold tracking-tight">
          Q-BOM<span className="text-[#00e5a0]">.</span>AI
        </div>
        <div className="text-[10px] text-[#6b7280] mt-0.5 uppercase tracking-widest">Quantum Auditor</div>
      </div>

      {/* Nav */}
      <nav className="flex-1 space-y-0.5">
        {NAV.map(item => (
          <button
            key={item.id}
            onClick={() => setCurrentPage(item.id)}
            className={clsx(
              'w-full flex items-center gap-2.5 px-5 py-2.5 text-left text-xs uppercase tracking-wider border-l-2 transition-all',
              currentPage === item.id
                ? 'text-[#00e5a0] border-[#00e5a0] bg-[#00e5a0]/[0.05]'
                : 'text-[#6b7280] border-transparent hover:text-[#e8eaf0] hover:bg-white/[0.02]'
            )}
          >
            <span className="text-[10px]">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>

      {/* Scan indicator */}
      {isScanRunning && (
        <div className="px-5 py-3 border-t border-white/[0.07]">
          <div className="flex items-center gap-2 text-[11px] text-[#38bdf8]">
            <span className="w-1.5 h-1.5 rounded-full bg-current animate-pulse" />
            Agents running…
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="px-5 pt-3 border-t border-white/[0.07] text-[10px] text-[#6b7280]">
        <div>v1.0.0</div>
        <div className="mt-0.5 text-[#6b7280]/50">LangGraph · Azure OpenAI</div>
      </div>
    </aside>
  )
}
