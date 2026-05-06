"""
main.py — FastAPI application entry point (final clean version).

All scan/risk/knowledge routes live in their respective router files.
This file only handles: app wiring, middleware, lifespan, and
system-level routes (/health, /eval/run, /retrieve shortcut).
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from config import get_settings
from models.db import init_db
from services.hybrid_retrieval import init_retrieval
from middleware.auth import AuthMiddleware, RequestLoggingMiddleware
from middleware.audit import AuditMiddleware
from observability.telemetry import setup_telemetry
from observability.logging_config import configure_logging
from routers import scan as scan_router
from routers import risk as risk_router
from routers import knowledge as knowledge_router
from routers import admin as admin_router
from tasks.scheduler import start_scheduler

settings = get_settings()
log = logging.getLogger("qbom")

# Configure structured logging immediately (before lifespan)
configure_logging(level="DEBUG" if settings.environment == "development" else "INFO")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    log.info("Q-BOM AI starting…")

    # 1. Database migrations / table creation
    await init_db()
    log.info("✓ Database ready")

    # 2. Build BM25 corpus from Postgres knowledge base
    await init_retrieval()
    log.info("✓ BM25 corpus loaded")

    # 3. Start background scheduler (nightly eval, hourly BM25 refresh, stall eviction)
    await start_scheduler()
    log.info("✓ Scheduler started")

    yield

    log.info("Q-BOM AI shutting down.")


app = FastAPI(
    title="Q-BOM AI",
    description="""
## Autonomous Quantum Cryptographic Bill of Materials Generator

Scans GitHub repositories and live websites for quantum-vulnerable cryptographic
primitives using a **multi-agent LangGraph pipeline**. Generates CycloneDX v1.7 CBOMs.

### Key capabilities
- **Multi-agent**: Supervisor → Scanner → Enricher → Reflector → Reporter
- **Hybrid retrieval**: BM25 + Dense (Pinecone) fused with Reciprocal Rank Fusion
- **Self-reflection**: Enricher re-runs automatically if quality score < 0.8
- **MCP integration**: Agents call Postgres via Model Context Protocol tools
- **Observability**: LangSmith traces + OpenTelemetry + DeepEval/RAGAS evals

### Authentication
Pass your API key via `X-API-Key` header or `Authorization: Bearer <key>`.  
Demo key: `qbom-demo-key-2025`
""",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── OpenTelemetry instrumentation (before middleware) ──────────────────────────
setup_telemetry(app)

# ── Middleware (outermost = applied last, so order here = reverse execution) ───
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "https://qbom.ai", "https://staging.qbom.ai"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(AuditMiddleware)
app.add_middleware(AuthMiddleware)

# ── Routers ────────────────────────────────────────────────────────────────────
app.include_router(scan_router.router)
app.include_router(risk_router.router)
app.include_router(knowledge_router.router)
app.include_router(admin_router.router)


# ── System routes ──────────────────────────────────────────────────────────────
@app.get("/api/health", tags=["system"], include_in_schema=True)
async def health():
    """Liveness probe. No auth required."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "environment": settings.environment,
    }


@app.get("/api/retrieve", tags=["knowledge"])
async def quick_retrieve(query: str = Query(..., min_length=2), top_k: int = Query(5, ge=1, le=20)):
    """
    Convenience GET wrapper for hybrid retrieval (no request body needed).
    Runs BM25 + Dense search fused via RRF.
    """
    from services.hybrid_retrieval import hybrid_retrieve
    docs = await hybrid_retrieve(query, top_k=top_k)
    return {
        "query": query,
        "results": [
            {
                "algorithm": d.algorithm,
                "content": d.content[:400],
                "source": d.source,
                "score": round(d.score, 4),
                "method": d.retrieval_method,
            }
            for d in docs
        ],
    }


@app.get("/api/eval/run", tags=["evaluation"])
async def trigger_eval():
    """
    Trigger a DeepEval + RAGAS evaluation pass over the last 20 completed scans.
    Results are also pushed to LangSmith as run feedback.
    """
    from models.db import AsyncSessionLocal, ScanRecord
    from sqlalchemy import select, desc
    from evaluation.harness import run_continuous_eval

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScanRecord)
            .where(ScanRecord.status == "complete")
            .order_by(desc(ScanRecord.created_at))
            .limit(20)
        )
        scans = [
            {"target": s.target, "enriched_findings": s.findings or []}
            for s in result.scalars().all()
        ]

    return await run_continuous_eval(scans)
