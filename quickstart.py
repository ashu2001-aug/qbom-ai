#!/usr/bin/env python3
"""
quickstart.py — Run Q-BOM AI locally with zero API keys.

Mocks: Azure OpenAI, Pinecone, LangGraph, sentence-transformers
Uses:  SQLite (no Postgres needed), in-memory BM25

Run:
  pip install -r backend/requirements-quickstart.txt
  python quickstart.py

Then open:
  Swagger UI:  http://localhost:8000/docs
  Dashboard:   open frontend/dashboard.html in your browser
  API key:     qbom-demo-key-2025
"""
import os, sys, json, uuid, asyncio, threading, time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

# ── Set env before ANY imports ────────────────────────────────────────────────
os.environ.update({
    "DATABASE_URL":              "sqlite+aiosqlite:///./qbom_local.db",
    "AZURE_OPENAI_API_KEY":      "mock",
    "AZURE_OPENAI_ENDPOINT":     "https://mock.openai.azure.com/",
    "AZURE_OPENAI_DEPLOYMENT":   "gpt-4o",
    "AZURE_OPENAI_API_VERSION":  "2024-08-01-preview",
    "LANGCHAIN_TRACING_V2":      "false",
    "LANGCHAIN_API_KEY":         "mock",
    "PINECONE_API_KEY":          "mock",
    "PINECONE_INDEX":            "qbom-local",
    "PINECONE_ENV":              "us-east-1",
    "ENVIRONMENT":               "development",
    "SCHEDULER_ENABLED":        "false",
    "SECRET_KEY":               "local-dev-secret",
})

ROOT    = Path(__file__).parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))

# ── Install deps if needed ────────────────────────────────────────────────────
def ensure_deps():
    needed = [
        ("fastapi",         "fastapi==0.115.0"),
        ("uvicorn",         "uvicorn[standard]==0.30.0"),
        ("sqlalchemy",      "sqlalchemy[asyncio]==2.0.35"),
        ("aiosqlite",       "aiosqlite==0.20.0"),
        ("httpx",           "httpx==0.27.0"),
        ("pydantic_settings","pydantic-settings==2.4.0"),
        ("dotenv",          "python-dotenv==1.0.1"),
        ("rank_bm25",       "rank-bm25==0.2.2"),
        ("bs4",             "beautifulsoup4==4.12.3"),
        ("git",             "gitpython==3.1.43"),
        ("numpy",           "numpy==1.26.4"),
    ]
    missing_pkgs = []
    for mod, pkg in needed:
        try:
            __import__(mod)
        except ImportError:
            missing_pkgs.append(pkg)
    if missing_pkgs:
        import subprocess
        print(f"Installing {len(missing_pkgs)} packages...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install"] + missing_pkgs + ["-q"],
            stdout=subprocess.DEVNULL
        )
        print("Done.\n")

ensure_deps()

# ── Stub heavy modules that aren't installed ──────────────────────────────────
import types, numpy as np

def _make_module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

# langchain stubs
for mod_name in [
    "langchain_core", "langchain_core.messages", "langchain_core.tools",
    "langchain_core.runnables", "langchain_core.runnables.config",
    "langchain", "langchain_openai", "langchain_community",
    "langgraph", "langgraph.graph", "langgraph.prebuilt",
    "langsmith",
    "pinecone", "sentence_transformers",
    "opentelemetry", "opentelemetry.sdk", "opentelemetry.sdk.trace",
    "opentelemetry.sdk.metrics", "opentelemetry.sdk.resources",
    "opentelemetry.instrumentation", "opentelemetry.instrumentation.fastapi",
    "opentelemetry.instrumentation.sqlalchemy", "opentelemetry.instrumentation.httpx",
    "opentelemetry.instrumentation.logging", "opentelemetry.exporter",
    "opentelemetry.exporter.otlp", "opentelemetry.exporter.otlp.proto",
    "opentelemetry.exporter.otlp.proto.grpc",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter",
    "deepeval", "ragas", "datasets", "mcp", "mcp.server",
    "mcp.server.models", "mcp.types", "mcp.server.stdio",
    "azure", "azure.identity",
    "cyclonedx", "cyclonedx.model", "cyclonedx.model.bom",
    "cyclonedx.model.component", "cyclonedx.model.crypto",
    "cyclonedx.output", "cyclonedx.output.json",
]:
    if mod_name not in sys.modules:
        _make_module(mod_name)

# Concrete stubs for things the code instantiates
class _AIMessage:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []

class _HumanMessage:
    def __init__(self, content=""): self.content = content

class _SystemMessage:
    def __init__(self, content=""): self.content = content

class _ToolMessage:
    def __init__(self, content="", tool_call_id=""): self.content = content; self.tool_call_id = tool_call_id

# Patch message classes
lc_msgs = sys.modules["langchain_core.messages"]
lc_msgs.BaseMessage   = _AIMessage
lc_msgs.AIMessage     = _AIMessage
lc_msgs.HumanMessage  = _HumanMessage
lc_msgs.SystemMessage = _SystemMessage
lc_msgs.ToolMessage   = _ToolMessage

# Mock tool decorator
def _tool(fn=None, **kw):
    if fn: fn.invoke = lambda args: fn(**args) if isinstance(args,dict) else fn(args); return fn
    return _tool
sys.modules["langchain_core.tools"].tool = _tool

# Mock RunnableConfig
class _RunnableConfig(dict): pass
sys.modules["langchain_core.runnables"].RunnableConfig = _RunnableConfig

# Mock AzureChatOpenAI
_RESPONSES = [
    "scanner",
    json.dumps([{
        "algorithm": "RSA-2048", "location": "auth.py:42",
        "hndl_score": 8.5, "quantum_vulnerable": True,
        "is_shadow_crypto": False, "migration_path": "ML-KEM-768 (FIPS 203)",
        "snippet": "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        "platform": "openssl"
    },{
        "algorithm": "SHA-1", "location": "utils/hash.py:15",
        "hndl_score": 5.0, "quantum_vulnerable": True,
        "is_shadow_crypto": False, "migration_path": "SHA-3-256",
        "snippet": "hashlib.sha1(data).hexdigest()",
        "platform": "hashlib"
    }]),
    "APPROVED - quality score 0.91, all findings validated",
    "reporter",
]
_n = [0]

class _MockLLM:
    def bind_tools(self, tools): return self
    async def ainvoke(self, messages, **kw):
        r = _RESPONSES[_n[0] % len(_RESPONSES)]; _n[0] += 1
        return _AIMessage(r)
    def invoke(self, messages, **kw):
        r = _RESPONSES[_n[0] % len(_RESPONSES)]; _n[0] += 1
        return _AIMessage(r)

sys.modules["langchain_openai"].AzureChatOpenAI = lambda **kw: _MockLLM()

# Mock LangGraph
import operator
from typing import Annotated, Sequence, Any

class _StateGraph:
    def __init__(self, state_type): self._nodes = {}; self._edges = []; self._entry = None; self._cond = {}
    def add_node(self, name, fn): self._nodes[name] = fn
    def add_edge(self, a, b): self._edges.append((a,b))
    def add_conditional_edges(self, src, fn, *a): self._cond[src] = fn
    def set_entry_point(self, name): self._entry = name
    def compile(self): return _CompiledGraph(self)

END = "__end__"

class _CompiledGraph:
    def __init__(self, g): self._g = g
    async def ainvoke(self, state, config=None):
        # Simple linear mock execution: supervisor→scanner→enricher→reflector→reporter
        g = self._g
        current = g._entry
        visited = set()
        while current and current != END and current not in visited:
            visited.add(current)
            fn = g._nodes.get(current)
            if fn:
                result = await fn(state)
                if result: state = result
            # routing
            if current in g._cond:
                nxt = g._cond[current](state)
                current = nxt if nxt != END else None
            else:
                # find edge
                nxt = next((b for a,b in g._g._edges if a == current), None)
                current = nxt
        return state

lg = sys.modules["langgraph.graph"]
lg.StateGraph = _StateGraph
lg.END = END

# Mock langgraph.prebuilt
class _ToolNode:
    def __init__(self, tools): self.tools = {t.name: t for t in tools if hasattr(t,'name')}
sys.modules["langgraph.prebuilt"].ToolNode = _ToolNode

# Mock langsmith traceable
sys.modules["langsmith"].traceable = lambda *a, **kw: (lambda fn: fn)
sys.modules["langsmith"].Client    = lambda **kw: MagicMock()

# Mock Pinecone
class _PineconeIndex:
    def __init__(self): self._store = {}
    def upsert(self, vectors, **kw):
        for v in vectors: self._store[v["id"]] = v
        return {"upserted_count": len(vectors)}
    def query(self, vector, top_k=5, include_metadata=True):
        items = list(self._store.values())[:top_k]
        return {"matches": [{"id": i["id"], "score": 0.85,
                              "metadata": i.get("metadata",{})} for i in items]}

class _Pinecone:
    _idx = _PineconeIndex()
    def __init__(self, **kw): pass
    def Index(self, name): return self._idx
    def list_indexes(self): return [type("I",(),{"name":"qbom-local"})()]

sys.modules["pinecone"].Pinecone = _Pinecone

# Mock sentence_transformers
class _SentenceTransformer:
    def __init__(self, *a, **kw): pass
    def encode(self, text, **kw): return np.random.rand(384).astype("float32")
sys.modules["sentence_transformers"].SentenceTransformer = _SentenceTransformer

# Mock OpenTelemetry (no-ops)
for attr in ["trace","metrics"]:
    m = _make_module(f"opentelemetry.{attr}")
    setattr(m, "get_tracer", lambda *a,**k: MagicMock())
    setattr(m, "get_meter",  lambda *a,**k: MagicMock())
    setattr(m, "set_tracer_provider", lambda *a,**k: None)
    setattr(m, "set_meter_provider",  lambda *a,**k: None)
sys.modules["opentelemetry.instrumentation.fastapi"].FastAPIInstrumentor = MagicMock()
sys.modules["opentelemetry.instrumentation.sqlalchemy"].SQLAlchemyInstrumentor = MagicMock()
sys.modules["opentelemetry.instrumentation.httpx"].HTTPXClientInstrumentor = MagicMock()

# Mock MCP
sys.modules["mcp.server"].Server = MagicMock
sys.modules["mcp.server.models"].InitializationOptions = MagicMock
sys.modules["mcp.types"].Tool = MagicMock
sys.modules["mcp.types"].TextContent = MagicMock
sys.modules["mcp.types"].CallToolResult = MagicMock
sys.modules["mcp.server.stdio"].stdio_server = MagicMock()

# Mock CycloneDX
sys.modules["cyclonedx.model.bom"].Bom = MagicMock
sys.modules["cyclonedx.model.component"].Component = MagicMock
sys.modules["cyclonedx.model.component"].ComponentType = MagicMock()
sys.modules["cyclonedx.model.crypto"].CryptoProperties = MagicMock
sys.modules["cyclonedx.model.crypto"].CryptoAlgorithmProperties = MagicMock
sys.modules["cyclonedx.model.crypto"].CryptoPrimitive = type("CP",(),{
    "PKE":"pke","BLOCK_CIPHER":"blockCipher","HASH":"hash","UNKNOWN":"unknown"
})()
sys.modules["cyclonedx.model.crypto"].CryptoAlgorithmMode = MagicMock()
sys.modules["cyclonedx.output.json"].JsonV1Dot7 = MagicMock

# Mock Azure identity
sys.modules["azure.identity"].DefaultAzureCredential = MagicMock

# Mock DeepEval / RAGAS
sys.modules["deepeval"].evaluate = MagicMock(return_value=MagicMock())
sys.modules["ragas"].evaluate = MagicMock(return_value={"faithfulness":0.91,"answer_relevancy":0.87})

# Mock datasets
sys.modules["datasets"].Dataset = MagicMock

print("✓ All heavy dependencies mocked")

# ── Patch services that use external clients ───────────────────────────────────
# Patch hybrid_retrieval to use in-memory BM25 only (no Pinecone)
from services import hybrid_retrieval as _hr
_orig_dense = _hr.dense_search
def _mock_dense(query, top_k=10):
    "Return empty dense results — BM25 only in quickstart"
    return []
_hr.dense_search = _mock_dense

# Patch Pinecone index getter
_hr.get_pinecone_index = lambda: _Pinecone._idx
_hr.get_embedder = lambda: _SentenceTransformer()

print("✓ Services patched for local mode")

# ── Now import and run the FastAPI app ────────────────────────────────────────
os.chdir(BACKEND)
from main import app
from models.db import init_db, AsyncSessionLocal
from services.hybrid_retrieval import init_retrieval

async def startup():
    await init_db()
    print("✓ SQLite database ready (qbom_local.db)")
    # Seed knowledge base
    try:
        from routers.knowledge import SEED_DOCS
        from models.db import CryptoKnowledgeChunk
        from sqlalchemy import select
        async with AsyncSessionLocal() as db:
            for doc in SEED_DOCS:
                existing = await db.execute(
                    select(CryptoKnowledgeChunk).where(
                        CryptoKnowledgeChunk.algorithm == doc["algorithm"]
                    )
                )
                if not existing.scalar_one_or_none():
                    chunk = CryptoKnowledgeChunk(
                        id=str(uuid.uuid4()),
                        algorithm=doc["algorithm"],
                        content=doc["content"],
                        source=doc["source"],
                    )
                    db.add(chunk)
            await db.commit()
        print(f"✓ Knowledge base seeded ({len(SEED_DOCS)} algorithms)")
    except Exception as e:
        print(f"  KB seed skipped: {e}")

    await init_retrieval()
    print("✓ BM25 corpus built")

asyncio.run(startup())

# ── Print banner ───────────────────────────────────────────────────────────────
print("""
╔══════════════════════════════════════════════════════════╗
║         Q-BOM AI  —  Local Mode (no API keys)           ║
║                                                          ║
║  Swagger UI:  http://localhost:8000/docs                 ║
║  Health:      http://localhost:8000/api/health           ║
║  Dashboard:   open frontend/dashboard.html in browser   ║
║                                                          ║
║  API key:     qbom-demo-key-2025                        ║
║  Press Ctrl+C to stop                                    ║
╚══════════════════════════════════════════════════════════╝
""")

# ── Run ────────────────────────────────────────────────────────────────────────
import uvicorn
uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
