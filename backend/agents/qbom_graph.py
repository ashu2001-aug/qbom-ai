"""
agents/qbom_graph.py — Stateful multi-agent system built with LangGraph.

Agent topology:
  ┌──────────────┐
  │  Supervisor  │  ← Routes work to specialist agents
  └──────┬───────┘
         │
  ┌──────┴──────────────────────────────────┐
  │              │              │            │
  ▼              ▼              ▼            ▼
Scanner       Enricher      Reflector    Reporter
Agent         Agent         Agent        Agent
(discovery)  (AI classify) (self-check) (BOM gen)

Each node in the graph is a stateful LangChain runnable.
LangSmith traces the full reasoning chain automatically via env vars.
"""
from __future__ import annotations

import json
import operator
from typing import Annotated, TypedDict, Literal, Sequence

from langchain_core.messages import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langsmith import traceable

from config import get_settings
from services.hybrid_retrieval import hybrid_retrieve
from services.scanner import clone_and_scan, scan_website

settings = get_settings()


# ── LLM Factory — supports Gemini (local) and Azure OpenAI (production) ───────
def _build_llm():
    """
    Constructs and returns the appropriate LLM client based on settings.
    Supports ChatGoogleGenerativeAI (Gemini) for local testing and
    AzureChatOpenAI for production workloads.
    """
    if settings.llm_provider == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        return ChatGoogleGenerativeAI(
            model=settings.gemini_model,
            google_api_key=settings.google_api_key,
            temperature=0.1,
            max_output_tokens=4096,
        )
    else:
        from langchain_openai import AzureChatOpenAI
        return AzureChatOpenAI(
            azure_endpoint=settings.azure_openai_endpoint,
            azure_deployment=settings.azure_openai_deployment,
            api_version=settings.azure_openai_api_version,
            api_key=settings.azure_openai_api_key,
            temperature=0.1,
            max_tokens=4096,
        )

llm = _build_llm()

# ── Shared Agent State ────────────────────────────────────────────────────────
class QBOMState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], operator.add]
    target: str
    target_type: str              # "repo" | "website"
    raw_findings: list[dict]
    enriched_findings: list[dict]
    reflection_passed: bool
    reflection_iterations: int
    bom_json: str
    hndl_score: float
    risk_level: str
    next_agent: str
    error: str | None


# ── Tool definitions (callable by agents via tool-calling) ────────────────────
@tool
async def scan_target(target: str, target_type: str) -> str:
    """
    Scan a GitHub repo or website URL for cryptographic primitives.
    
    This function delegates the scanning process to:
    - clone_and_scan: for GitHub repositories ("repo")
    - scan_website: for URLs/websites ("website")
    
    Returns the scan findings serialized as a JSON string.
    """
    if target_type == "repo":
        findings = await clone_and_scan(target)
    else:
        findings = await scan_website(target)
    return json.dumps(findings)


@tool
async def retrieve_crypto_knowledge(query: str) -> str:
    """
    Hybrid BM25 + dense retrieval of cryptographic algorithm documentation.
    
    Uses hybrid_retrieve to search local/dense database for documentation on 
    the given algorithm query, retrieving the top 3 documents, and returns 
    them as a JSON string containing the algorithm name, content excerpt, and retrieval score.
    """
    docs = await hybrid_retrieve(query, top_k=3)
    return json.dumps([
        {"algorithm": d.algorithm, "content": d.content[:500], "score": d.score}
        for d in docs
    ])


@tool
def calculate_hndl_score(algorithm: str, data_sensitivity: str, exposure_years: int = 10) -> float:
    """
    Chain-of-Thought HNDL risk calculation.
    Returns 0-10 risk score for Harvest-Now-Decrypt-Later threat.
    
    Calculates the score based on:
    - Base vulnerability of the algorithm (e.g. RSA is higher risk than AES-256).
    - Sensitivity multiplier of the associated data (e.g. critical/financial vs public).
    - Time-to-exposure factor relative to the estimated CRQC (Cryptanalytically Relevant Quantum Computer) timeline.
    """
    # Quantum vulnerability weight
    VULN_WEIGHTS = {
        "RSA": 9.0, "ECC": 8.5, "ECDSA": 8.5, "ECDH": 8.0,
        "DH": 7.5, "DSA": 7.0, "AES-128": 3.0, "SHA-1": 4.0,
        "MD5": 5.0, "AES-256": 1.0, "SHA-256": 0.5,
    }
    SENSITIVITY_WEIGHTS = {
        "public": 1.0, "internal": 3.0, "confidential": 6.0,
        "medical": 9.0, "financial": 9.5, "critical": 10.0
    }
    crqc_years_away = max(0, 2032 - 2025)  # ~7 years
    time_factor = min(1.0, exposure_years / crqc_years_away) if crqc_years_away > 0 else 1.0

    algo_base = max(
        (VULN_WEIGHTS.get(k, 0) for k in VULN_WEIGHTS if k in algorithm.upper()),
        default=2.0
    )
    sens_multiplier = SENSITIVITY_WEIGHTS.get(data_sensitivity.lower(), 3.0) / 10.0
    score = algo_base * sens_multiplier * (0.5 + 0.5 * time_factor)
    return round(min(10.0, score), 2)


@tool
def get_migration_guidance(algorithm: str) -> str:
    """
    Return NIST-recommended post-quantum migration path for an algorithm.
    
    Checks the specified algorithm name against a pre-defined mapping of classical
    algorithms (such as RSA, ECC, AES-128, etc.) to their post-quantum alternatives
    (like ML-KEM, ML-DSA, SLH-DSA, etc.), target implementation timelines, and required effort.
    Returns the recommendation as a JSON-serialized dictionary.
    """
    MIGRATIONS = {
        "RSA": {
            "replace_with": "ML-KEM-768 (FIPS 203)",
            "deadline": "2030 (CNSA 2.0)",
            "effort": "high",
            "notes": "Key encapsulation only; pair with ML-DSA for signatures"
        },
        "ECC": {
            "replace_with": "ML-DSA-65 (FIPS 204)",
            "deadline": "2030 (CNSA 2.0)",
            "effort": "medium",
            "notes": "Drop-in for ECDSA in most TLS stacks"
        },
        "ECDSA": {
            "replace_with": "ML-DSA-65 (FIPS 204)",
            "deadline": "2030 (CNSA 2.0)",
            "effort": "medium",
            "notes": "Drop-in replacement for ECDSA signatures in most application stacks"
        },
        "AES-128": {
            "replace_with": "AES-256",
            "deadline": "2025 (immediate)",
            "effort": "low",
            "notes": "Grover halves effective key length; 128-bit AES → 64-bit quantum"
        },
        "SHA-1": {
            "replace_with": "SHA-3-256 or SHA-256",
            "deadline": "Immediate",
            "effort": "low",
            "notes": "Already classically broken; urgent"
        },
    }
    for key, val in MIGRATIONS.items():
        if key in algorithm.upper():
            return json.dumps(val)
    return json.dumps({"replace_with": "Evaluate NIST PQC round 4", "effort": "unknown"})


TOOLS = [scan_target, retrieve_crypto_knowledge, calculate_hndl_score, get_migration_guidance]
tool_node = ToolNode(TOOLS)
llm_with_tools = llm.bind_tools(TOOLS)


# ── Agent Node Functions ───────────────────────────────────────────────────────
@traceable(name="supervisor_agent")
async def supervisor_node(state: QBOMState) -> QBOMState:
    """
    Supervisor: reads current state and decides which specialist agent
    to invoke next. Uses Chain-of-Thought reasoning via system prompt.
    
    Reads progress from the QBOMState and generates the next_agent transition
    ("scanner", "enricher", "reflector", "reporter", or "end") by asking
    the LLM to analyze the current state summary.
    """
    system = SystemMessage(content="""You are the Q-BOM AI Supervisor. Your job is to orchestrate a 
quantum cryptography audit pipeline. Based on the current state, decide the next step.

Available agents:
- "scanner": Runs when raw_findings is empty
- "enricher": Runs when raw_findings exist but enriched_findings is empty  
- "reflector": Validates enriched findings quality (runs up to 2 times)
- "reporter": Generates the final CycloneDX BOM (runs last)
- "end": Pipeline complete

Think step by step. State your reasoning then output ONLY the agent name on the last line.""")

    state_summary = f"""
Current state:
- Target: {state['target']} ({state['target_type']})
- Raw findings: {len(state.get('raw_findings', []))} items
- Enriched findings: {len(state.get('enriched_findings', []))} items
- Reflection passed: {state.get('reflection_passed', False)}
- Reflection iterations: {state.get('reflection_iterations', 0)}
- BOM generated: {bool(state.get('bom_json'))}
- Error: {state.get('error')}
"""
    response = await llm.ainvoke([system, HumanMessage(content=state_summary)])
    next_agent = response.content.strip().split("\n")[-1].strip().lower()

    valid_agents = {"scanner", "enricher", "reflector", "reporter", "end"}
    if next_agent not in valid_agents:
        next_agent = "scanner" if not state.get("raw_findings") else "enricher"

    return {**state, "next_agent": next_agent, "messages": [response]}


@traceable(name="scanner_agent")
async def scanner_node(state: QBOMState) -> QBOMState:
    """
    Invokes the scan tool and populates raw_findings.
    
    Runs a tool-calling LLM to invoke the `scan_target` tool. If a tool call is generated,
    it executes `scan_target` using the state's target and target_type, parses the findings,
    and updates the state with the raw findings list.
    """
    system = SystemMessage(content="""You are the Scanner Agent. Your task is to scan the target 
for ALL cryptographic primitives. Use the scan_target tool. Be thorough.""")

    response = await llm_with_tools.ainvoke([
        system,
        HumanMessage(content=f"Scan this target: {state['target']} (type: {state['target_type']})")
    ])

    # If the LLM made a tool call, execute it
    raw_findings = state.get("raw_findings", [])
    if response.tool_calls:
        for tc in response.tool_calls:
            if tc["name"] == "scan_target":
                result = await scan_target.ainvoke(tc["args"])
                raw_findings = json.loads(result)

    return {**state, "raw_findings": raw_findings, "messages": [response]}


@traceable(name="enricher_agent")
async def enricher_node(state: QBOMState) -> QBOMState:
    """
    Enricher: for each raw finding, uses hybrid retrieval + tool-calling to:
    1. Classify quantum vulnerability
    2. Calculate HNDL risk score
    3. Fetch migration guidance
    4. Detect shadow crypto via CoT reasoning
    
    Runs an agentic loop (up to 10 rounds) allowing the LLM to call tools
    for background knowledge, risk scoring, and migration paths. Finally,
    parses and extracts a structured JSON list of enriched findings.
    """
    system = SystemMessage(content="""You are the Cryptographic Enricher Agent. 
For each finding, you MUST:
1. Call retrieve_crypto_knowledge to get context about the algorithm
2. Call calculate_hndl_score with appropriate sensitivity
3. Call get_migration_guidance for each quantum-vulnerable algorithm
4. Determine if this is "shadow crypto" (informal, non-standard implementation)

Use Chain-of-Thought: think out loud before calling each tool.
Return a JSON array of enriched findings when done.""")

    findings_text = json.dumps(state["raw_findings"], indent=2)

    messages = [
        system,
        HumanMessage(content=f"Enrich these cryptographic findings:\n{findings_text}")
    ]

    # Agentic loop: keep calling tools until LLM stops making tool calls
    enriched = []
    for _ in range(10):   # max tool-call rounds
        response = await llm_with_tools.ainvoke(messages)
        messages.append(response)

        if not response.tool_calls:
            # Extract enriched JSON from final response
            try:
                content = response.content
                # Strip markdown fences if present
                if "```" in content:
                    content = content.split("```")[1].lstrip("json").strip()
                enriched = json.loads(content)
            except Exception:
                enriched = state["raw_findings"]  # fallback
            break

        # Execute tool calls and add results to messages
        from langchain_core.messages import ToolMessage
        for tc in response.tool_calls:
            tool_map = {t.name: t for t in TOOLS}
            if tc["name"] in tool_map:
                result = await tool_map[tc["name"]].ainvoke(tc["args"])
                messages.append(ToolMessage(content=str(result), tool_call_id=tc["id"]))

    return {**state, "enriched_findings": enriched, "messages": messages[-3:]}


@traceable(name="reflector_agent")
async def reflector_node(state: QBOMState) -> QBOMState:
    """
    Self-Reflection Loop: critiques the enricher's output for:
    - Completeness (are all algorithms covered?)
    - Accuracy (do HNDL scores seem reasonable?)
    - False positives (is shadow crypto detection correct?)
    
    If quality < threshold, signals enricher to re-run.
    Max 2 reflection iterations to prevent infinite loops.
    
    Uses the LLM to analyze the enriched findings. If the LLM approves,
    sets `reflection_passed` to True; otherwise, sets it to False to trigger a retry.
    """
    iterations = state.get("reflection_iterations", 0)
    if iterations >= 2:
        # Force pass after max iterations
        return {**state, "reflection_passed": True, "reflection_iterations": iterations}

    system = SystemMessage(content="""You are the QA Reflector Agent. Critically evaluate 
the enriched cryptographic findings for quality. Check:

1. Are HNDL scores 0-10 and contextually reasonable?
2. Are migration paths correctly assigned?
3. Is shadow crypto detection plausible?
4. Are there obvious false positives or missed algorithms?

If quality is acceptable (>=80%), respond with: APPROVED
If quality needs improvement, respond with: RETRY - [specific issues to fix]""")

    response = await llm.ainvoke([
        system,
        HumanMessage(content=f"Evaluate these findings:\n{json.dumps(state['enriched_findings'], indent=2)}")
    ])

    passed = "APPROVED" in response.content.upper()

    return {
        **state,
        "reflection_passed": passed,
        "reflection_iterations": iterations + 1,
        "messages": [response]
    }


@traceable(name="reporter_agent")
async def reporter_node(state: QBOMState) -> QBOMState:
    """
    Reporter: generates the final CycloneDX v1.7 CBOM and computes
    aggregate risk metrics.
    
    Constructs a structured CycloneDX 1.7 JSON Bill of Materials containing
    cryptographic asset details, locations, custom HNDL score properties, and migration paths.
    Also calculates aggregate HNDL scores and overall risk level ("critical", "high", etc.).
    """
    findings = state["enriched_findings"]

    # Calculate aggregate HNDL score
    scores = [f.get("hndl_score", 0) for f in findings if isinstance(f, dict)]
    avg_hndl = sum(scores) / len(scores) if scores else 0
    max_hndl = max(scores) if scores else 0

    risk_level = (
        "critical" if max_hndl >= 8.0 else
        "high" if max_hndl >= 6.0 else
        "medium" if max_hndl >= 4.0 else
        "low"
    )

    # Generate CycloneDX BOM structure
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "serialNumber": f"urn:uuid:{state['target'].replace('https://', '').replace('/', '-')}",
        "metadata": {
            "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
            "tools": [{"name": "Q-BOM AI", "version": "1.0.0"}],
            "component": {"type": "application", "name": state["target"]}
        },
        "components": [
            {
                "type": "cryptographic-asset",
                "name": f.get("algorithm", "unknown"),
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": f.get("primitive", "unknown"),
                        "parameterSetIdentifier": f.get("algorithm", ""),
                        "executionEnvironment": "application",
                        "implementationPlatform": f.get("platform", "unknown"),
                        "certificationLevel": [],
                        "quantumVulnerable": f.get("quantum_vulnerable", True),
                    },
                },
                "properties": [
                    {"name": "hndl_score", "value": str(f.get("hndl_score", 0))},
                    {"name": "location", "value": f.get("location", "")},
                    {"name": "is_shadow_crypto", "value": str(f.get("is_shadow_crypto", False))},
                    {"name": "migration_path", "value": json.dumps(f.get("migration", {}))},
                    {"name": "risk_level", "value": f.get("risk_level", "unknown")},
                ]
            }
            for f in findings if isinstance(f, dict)
        ],
        "qbomMeta": {
            "avgHndlScore": round(avg_hndl, 2),
            "maxHndlScore": round(max_hndl, 2),
            "riskLevel": risk_level,
            "totalFindings": len(findings),
            "quantumVulnerableCount": sum(1 for f in findings if isinstance(f, dict) and f.get("quantum_vulnerable")),
        }
    }

    return {
        **state,
        "bom_json": json.dumps(bom, indent=2),
        "hndl_score": avg_hndl,
        "risk_level": risk_level,
        "next_agent": "end"
    }


# ── Edge routing logic ────────────────────────────────────────────────────────
def route_from_supervisor(state: QBOMState) -> Literal["scanner", "enricher", "reflector", "reporter", END]:
    """
    Conditional router for the supervisor node.
    
    Reads the `next_agent` value determined by the supervisor and returns
    the corresponding graph node or the END state symbol to terminate.
    """
    next_a = state.get("next_agent", "scanner")
    if next_a == "end":
        return END
    return next_a


def route_from_reflector(state: QBOMState) -> Literal["enricher", "reporter"]:
    """
    Conditional router for the reflector QA node.
    
    If self-reflection passed validation (`reflection_passed` is True),
    routes to the "reporter" node to build the final BOM. Otherwise, routes
    back to the "enricher" node to correct the findings.
    """
    if state.get("reflection_passed"):
        return "reporter"
    return "enricher"  # Re-enrich if reflection failed


# ── Build the LangGraph ───────────────────────────────────────────────────────
def build_qbom_graph() -> StateGraph:
    """
    Constructs, wires, and compiles the LangGraph state machine.
    
    Declares all nodes (supervisor, scanner, enricher, reflector, reporter),
    defines the entry point, and configures the transitions and conditional router edges.
    Returns the compiled graph.
    """
    graph = StateGraph(QBOMState)

    graph.add_node("supervisor", supervisor_node)
    graph.add_node("scanner", scanner_node)
    graph.add_node("enricher", enricher_node)
    graph.add_node("reflector", reflector_node)
    graph.add_node("reporter", reporter_node)

    graph.set_entry_point("supervisor")

    graph.add_conditional_edges("supervisor", route_from_supervisor)
    graph.add_edge("scanner", "supervisor")
    graph.add_edge("enricher", "reflector")
    graph.add_conditional_edges("reflector", route_from_reflector)
    graph.add_edge("reporter", END)

    return graph.compile()


# Compiled graph — import this in the API routers
qbom_graph = build_qbom_graph()


async def run_scan(target: str, target_type: str = "repo") -> QBOMState:
    """
    Entry point to execute the full multi-agent scan pipeline.
    LangSmith will trace this run under the project set in LANGCHAIN_PROJECT.
    
    Initializes the QBOMState and executes the compiled `qbom_graph`
    using the provided target (GitHub repository or website URL) and target type.
    """
    import os
    from langchain_core.runnables import RunnableConfig

    run_name = f"qbom-scan-{target_type}-{target.split('/')[-1][:30]}"

    config = RunnableConfig(
        run_name=run_name,
        tags=["qbom", f"target:{target_type}"],
        metadata={"target": target, "target_type": target_type},
    )

    initial_state: QBOMState = {
        "messages": [HumanMessage(content=f"Scan {target_type}: {target}")],
        "target": target,
        "target_type": target_type,
        "raw_findings": [],
        "enriched_findings": [],
        "reflection_passed": False,
        "reflection_iterations": 0,
        "bom_json": "",
        "hndl_score": 0.0,
        "risk_level": "unknown",
        "next_agent": "scanner",
        "error": None,
    }
    return await qbom_graph.ainvoke(initial_state, config=config)
