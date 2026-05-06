/**
 * components/agents/AgentTrace.tsx — LangGraph pipeline visualizer.
 * Shows agent nodes, routing decisions, tool calls, and retrieval results.
 */
import React, { useState } from 'react'
import { useRetrieve } from '@/lib/api'
import { Card, CardTitle, PageHeader, Spinner, Badge } from '@/components/shared'
import clsx from 'clsx'

const AGENTS = [
  {
    name: 'Supervisor',
    color: '#38bdf8',
    icon: '⊕',
    desc: 'CoT routing engine — reads state and decides which specialist to invoke next',
    detail: 'Uses Azure GPT-4o with chain-of-thought prompting. Reads the full QBOMState and outputs the name of the next agent. Runs after every other agent to re-evaluate routing.',
  },
  {
    name: 'Scanner',
    color: '#00e5a0',
    icon: '⊙',
    desc: 'Crypto primitive discovery — regex + CodeQL + JS bundle analysis',
    detail: 'Clones repos with GitPython (depth=1). Runs 20+ regex patterns across 90+ file extensions. Invokes CodeQL CLI for AST-level analysis. For websites: TLS inspection, header audit, JS bundle scanning.',
  },
  {
    name: 'Enricher',
    color: '#f59e0b',
    icon: '⊛',
    desc: 'Tool-calling loop — hybrid retrieval → HNDL scoring → migration guidance',
    detail: 'Agentic tool-calling loop (max 10 rounds). Calls: retrieve_crypto_knowledge (BM25+Dense), calculate_hndl_score, get_migration_guidance, MCP database save_finding. Detects shadow crypto via CoT reasoning.',
  },
  {
    name: 'Reflector',
    color: '#ff4d6d',
    icon: '⊗',
    desc: 'Self-reflection loop — quality check, max 2 retries before Reporter',
    detail: 'Evaluates enriched findings for: HNDL score plausibility, migration path accuracy, false-positive shadow crypto, missed algorithms. If quality < 0.8 → routes back to Enricher. Max 2 iterations.',
  },
  {
    name: 'Reporter',
    color: '#38bdf8',
    icon: '⊘',
    desc: 'Output generation — CycloneDX v1.7 CBOM + risk metrics',
    detail: 'Constructs a full CycloneDX v1.7 CBOM with cryptoProperties, quantumVulnerable flags, and vulnerability entries. Calculates aggregate HNDL metrics and risk level classification.',
  },
]

const TOOLS = [
  { name: 'scan_target',               caller: 'Scanner',  type: 'I/O',    desc: 'Clone repo / fetch website, run regex + CodeQL' },
  { name: 'retrieve_crypto_knowledge', caller: 'Enricher', type: 'Hybrid', desc: 'BM25 + Dense (Pinecone) via RRF — returns top-k docs' },
  { name: 'calculate_hndl_score',      caller: 'Enricher', type: 'Compute',desc: 'HNDL risk 0–10 from algo + sensitivity + exposure' },
  { name: 'get_migration_guidance',    caller: 'Enricher', type: 'Lookup', desc: 'NIST FIPS migration path for each vulnerable algorithm' },
  { name: 'save_finding (MCP)',        caller: 'Enricher', type: 'MCP',    desc: 'Persists findings to Postgres via Model Context Protocol' },
  { name: 'query_crypto_knowledge (MCP)', caller: 'Supervisor', type: 'MCP', desc: 'Reads knowledge base via MCP database tool' },
]

export function AgentTrace() {
  const [query, setQuery]         = useState('')
  const [activeAgent, setActiveAgent] = useState<string | null>(null)
  const retrieve = useRetrieve()

  return (
    <div>
      <PageHeader
        title="LangGraph Agent Trace"
        sub="Multi-agent pipeline · self-reflection loops · tool-calling · MCP integration"
      />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 mb-5">
        {/* ── Pipeline diagram ── */}
        <Card>
          <CardTitle>Agent pipeline</CardTitle>

          {/* Flow diagram */}
          <div className="flex flex-col gap-0 mb-5">
            {AGENTS.map((agent, i) => (
              <div key={agent.name}>
                <div
                  className={clsx(
                    'flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-colors',
                    activeAgent === agent.name ? 'bg-white/[0.04]' : 'hover:bg-white/[0.02]'
                  )}
                  onClick={() => setActiveAgent(activeAgent === agent.name ? null : agent.name)}
                >
                  <div
                    className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5"
                    style={{ background: `${agent.color}20`, color: agent.color, border: `1px solid ${agent.color}40` }}
                  >
                    {agent.icon}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-xs uppercase tracking-wider" style={{ color: agent.color }}>
                        {agent.name}
                      </span>
                      <Badge variant="complete">✓</Badge>
                    </div>
                    <p className="text-[11px] text-[#6b7280] mt-0.5">{agent.desc}</p>
                    {activeAgent === agent.name && (
                      <p className="text-[11px] text-[#e8eaf0]/70 mt-2 leading-relaxed border-l-2 border-white/10 pl-2">
                        {agent.detail}
                      </p>
                    )}
                  </div>
                </div>
                {i < AGENTS.length - 1 && (
                  <div className="flex items-center gap-3 ml-3.5 py-0.5">
                    <div className="w-1 h-4 ml-3.5 border-l border-dashed border-white/10" />
                    {i === 3 && (
                      <span className="text-[10px] text-[#6b7280] -ml-2">if quality &lt; 0.8 → back to Enricher</span>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* State transitions */}
          <div className="bg-[#151922] rounded-lg p-3 font-mono text-[11px] text-[#6b7280] leading-relaxed">
            <div className="text-[#00e5a0] mb-1">// LangGraph state routing</div>
            <div><span className="text-[#38bdf8]">supervisor</span> → scanner        <span className="text-white/30"># raw_findings empty</span></div>
            <div><span className="text-[#38bdf8]">scanner</span>    → supervisor      <span className="text-white/30"># always returns to supervisor</span></div>
            <div><span className="text-[#38bdf8]">supervisor</span> → enricher        <span className="text-white/30"># findings exist, enriched empty</span></div>
            <div><span className="text-[#38bdf8]">enricher</span>   → reflector       <span className="text-white/30"># always</span></div>
            <div><span className="text-[#38bdf8]">reflector</span>  → enricher        <span className="text-white/30"># quality &lt; 0.8, iter &lt; 2</span></div>
            <div><span className="text-[#38bdf8]">reflector</span>  → reporter        <span className="text-white/30"># quality ≥ 0.8 or iter == 2</span></div>
            <div><span className="text-[#38bdf8]">reporter</span>   → END             <span className="text-white/30"># BOM generated</span></div>
          </div>
        </Card>

        {/* ── Tool registry ── */}
        <Card>
          <CardTitle>Tool registry</CardTitle>
          <div className="space-y-2">
            {TOOLS.map(tool => (
              <div key={tool.name} className="flex gap-3 p-2.5 bg-[#151922] rounded-lg">
                <div className="shrink-0">
                  <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase tracking-wider', {
                    'bg-violet-400/10 text-violet-400': tool.type === 'MCP',
                    'bg-amber-400/10 text-amber-400':  tool.type === 'Hybrid',
                    'bg-sky-400/10 text-sky-400':      tool.type === 'Compute',
                    'bg-emerald-400/10 text-emerald-400': tool.type === 'I/O',
                    'bg-white/5 text-[#6b7280]':       tool.type === 'Lookup',
                  })}>
                    {tool.type}
                  </span>
                </div>
                <div className="min-w-0">
                  <div className="font-mono text-xs font-semibold truncate">{tool.name}</div>
                  <div className="text-[11px] text-[#6b7280] mt-0.5">{tool.desc}</div>
                  <div className="text-[10px] text-[#6b7280]/60 mt-0.5">caller: {tool.caller}</div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* ── Live hybrid retrieval tester ── */}
      <Card>
        <CardTitle>Hybrid retrieval tester (BM25 + Dense → RRF)</CardTitle>
        <div className="flex gap-2 mb-4">
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && retrieve.mutate({ query, topK: 5 })}
            placeholder="e.g. RSA quantum vulnerability migration path"
            className="flex-1 bg-[#151922] border border-white/10 rounded-lg px-3.5 py-2.5 text-xs font-mono outline-none focus:border-[#00e5a0] transition-colors"
          />
          <button
            onClick={() => retrieve.mutate({ query, topK: 5 })}
            disabled={!query.trim() || retrieve.isPending}
            className="bg-[#00e5a0] text-black px-4 py-2.5 rounded-lg text-xs font-semibold disabled:opacity-40 flex items-center gap-2"
          >
            {retrieve.isPending ? <Spinner size={14} /> : null} Retrieve
          </button>
        </div>

        {retrieve.data && (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {retrieve.data.results.map((doc: any, i: number) => (
              <div key={i} className="bg-[#151922] rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <span className="font-semibold text-xs">{doc.algorithm}</span>
                  <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase', {
                    'bg-amber-400/10 text-amber-400': doc.method === 'hybrid',
                    'bg-sky-400/10 text-sky-400':     doc.method === 'dense',
                    'bg-violet-400/10 text-violet-400': doc.method === 'bm25',
                  })}>
                    {doc.method}
                  </span>
                </div>
                <div className="text-[11px] text-[#6b7280] leading-relaxed line-clamp-4">{doc.content}</div>
                <div className="flex items-center justify-between mt-2 pt-2 border-t border-white/[0.06]">
                  <span className="text-[10px] text-[#6b7280]">{doc.source}</span>
                  <span className="text-[10px] text-[#00e5a0] font-semibold">RRF {doc.score.toFixed(4)}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
