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
    "LLM_PROVIDER":              "azure",
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

# ── Stub ONLY modules that aren't actually installed ──────────────────────────
import types, numpy as np

def _make_module(name):
    m = types.ModuleType(name)
    sys.modules[name] = m
    return m

def _get_mod(name):
    """Get module from sys.modules, or create a stub if missing."""
    if name in sys.modules:
        return sys.modules[name]
    return _make_module(name)

# Only stub modules whose root package is NOT installed
_OPTIONAL_MODULES = [
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
]
for mod_name in _OPTIONAL_MODULES:
    root_pkg = mod_name.split(".")[0]
    try:
        __import__(root_pkg)
    except Exception:
        if mod_name not in sys.modules:
            _make_module(mod_name)

# ── Mock LLM (use real langchain classes, fake responses only) ────────────────
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

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
    """Drop-in replacement for AzureChatOpenAI that returns canned responses."""
    def bind_tools(self, tools): return self
    async def ainvoke(self, messages, **kw):
        r = _RESPONSES[_n[0] % len(_RESPONSES)]; _n[0] += 1
        msg = AIMessage(content=r); msg.tool_calls = []; return msg
    def invoke(self, messages, **kw):
        r = _RESPONSES[_n[0] % len(_RESPONSES)]; _n[0] += 1
        msg = AIMessage(content=r); msg.tool_calls = []; return msg

# Patch AzureChatOpenAI to return our mock LLM
import langchain_openai
langchain_openai.AzureChatOpenAI = lambda **kw: _MockLLM()

# Patch langsmith traceable to be a no-op decorator (avoid tracing calls)
import langsmith
langsmith.traceable = lambda *a, **kw: (lambda fn: fn)
langsmith.Client = lambda **kw: MagicMock()

# Helper: get module from sys.modules or create a stub
def _get_mod(name):
    if name in sys.modules:
        return sys.modules[name]
    return _make_module(name)

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

_get_mod("pinecone").Pinecone = _Pinecone

# Mock sentence_transformers
class _SentenceTransformer:
    def __init__(self, *a, **kw): pass
    def encode(self, text, **kw): return np.random.rand(384).astype("float32")
_get_mod("sentence_transformers").SentenceTransformer = _SentenceTransformer

# Mock OpenTelemetry (no-ops)
for attr in ["trace","metrics"]:
    m = _get_mod(f"opentelemetry.{attr}")
    setattr(m, "get_tracer", lambda *a,**k: MagicMock())
    setattr(m, "get_meter",  lambda *a,**k: MagicMock())
    setattr(m, "set_tracer_provider", lambda *a,**k: None)
    setattr(m, "set_meter_provider",  lambda *a,**k: None)
_get_mod("opentelemetry.instrumentation.fastapi").FastAPIInstrumentor = MagicMock()
_get_mod("opentelemetry.instrumentation.sqlalchemy").SQLAlchemyInstrumentor = MagicMock()
_get_mod("opentelemetry.instrumentation.httpx").HTTPXClientInstrumentor = MagicMock()

# Mock MCP
_get_mod("mcp.server").Server = MagicMock
_get_mod("mcp.server.models").InitializationOptions = MagicMock
_get_mod("mcp.types").Tool = MagicMock
_get_mod("mcp.types").TextContent = MagicMock
_get_mod("mcp.types").CallToolResult = MagicMock
_get_mod("mcp.server.stdio").stdio_server = MagicMock()

# Mock CycloneDX
_get_mod("cyclonedx.model.bom").Bom = MagicMock
_get_mod("cyclonedx.model.component").Component = MagicMock
_get_mod("cyclonedx.model.component").ComponentType = MagicMock()
_get_mod("cyclonedx.model.crypto").CryptoProperties = MagicMock
_get_mod("cyclonedx.model.crypto").CryptoAlgorithmProperties = MagicMock
_get_mod("cyclonedx.model.crypto").CryptoPrimitive = type("CP",(),{
    "PKE":"pke","BLOCK_CIPHER":"blockCipher","HASH":"hash","UNKNOWN":"unknown"
})()
_get_mod("cyclonedx.model.crypto").CryptoAlgorithmMode = MagicMock()
_get_mod("cyclonedx.output.json").JsonV1Dot7 = MagicMock

# Mock Azure identity
_get_mod("azure.identity").DefaultAzureCredential = MagicMock

# Mock DeepEval / RAGAS
_get_mod("deepeval").evaluate = MagicMock(return_value=MagicMock())
_get_mod("ragas").evaluate = MagicMock(return_value={"faithfulness":0.91,"answer_relevancy":0.87})

# Mock datasets
_get_mod("datasets").Dataset = MagicMock

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
