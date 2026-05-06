"""
backend/tasks/scheduler.py — Background periodic tasks.

Tasks:
  - Every hour:   Rebuild BM25 corpus from Postgres (picks up new knowledge docs)
  - Every night:  Run DeepEval + RAGAS evaluation batch over last 24h of scans
  - Every 5 min:  Evict stalled scans (queued > 15 min → mark failed)

Uses asyncio background loops started at FastAPI lifespan.
In production on AKS, only one replica should run scheduled tasks
(set SCHEDULER_ENABLED=true on exactly one pod via env/ConfigMap).
"""
from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, update

log = logging.getLogger("qbom.scheduler")
SCHEDULER_ENABLED = os.getenv("SCHEDULER_ENABLED", "false").lower() == "true"


async def _rebuild_bm25():
    """Rebuild the BM25 in-memory corpus from the latest Postgres knowledge base."""
    from services.hybrid_retrieval import init_retrieval
    try:
        await init_retrieval()
        log.info("BM25 corpus rebuilt successfully")
    except Exception as e:
        log.error(f"BM25 rebuild failed: {e}")


async def _run_nightly_eval():
    """Run DeepEval + RAGAS evaluation batch over the last 24h of scans."""
    from models.db import AsyncSessionLocal, ScanRecord
    from evaluation.harness import run_continuous_eval

    try:
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ScanRecord)
                .where(ScanRecord.status == "complete")
                .where(ScanRecord.created_at >= since)
                .order_by(ScanRecord.created_at.desc())
                .limit(50)
            )
            scans = [
                {"target": s.target, "enriched_findings": s.findings or []}
                for s in result.scalars().all()
            ]

        if scans:
            scores = await run_continuous_eval(scans)
            log.info(f"Nightly eval complete: {scores}")
        else:
            log.info("No scans in last 24h — skipping eval")
    except Exception as e:
        log.error(f"Nightly eval failed: {e}")


async def _evict_stalled_scans():
    """Mark scans that have been 'queued' or 'scanning' for > 15 minutes as failed."""
    from models.db import AsyncSessionLocal, ScanRecord

    try:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                update(ScanRecord)
                .where(ScanRecord.status.in_(["queued", "scanning"]))
                .where(ScanRecord.created_at < cutoff)
                .values(status="failed", findings={"error": "Scan timed out after 15 minutes"})
                .returning(ScanRecord.id)
            )
            evicted = result.scalars().all()
            if evicted:
                await db.commit()
                log.warning(f"Evicted {len(evicted)} stalled scans: {evicted}")
    except Exception as e:
        log.error(f"Eviction failed: {e}")


# ── Scheduler loops ────────────────────────────────────────────────────────────
async def _every(seconds: int, task_fn, name: str):
    """Run task_fn every `seconds` seconds, logging errors without crashing."""
    while True:
        await asyncio.sleep(seconds)
        log.debug(f"Running scheduled task: {name}")
        await task_fn()


async def start_scheduler():
    """
    Start all background task loops.
    Call from FastAPI lifespan if SCHEDULER_ENABLED=true.
    """
    if not SCHEDULER_ENABLED:
        log.info("Scheduler disabled (SCHEDULER_ENABLED != true)")
        return

    log.info("Starting Q-BOM AI background scheduler")
    asyncio.create_task(_every(3600,      _rebuild_bm25,        "bm25_rebuild"))
    asyncio.create_task(_every(86400,     _run_nightly_eval,    "nightly_eval"))
    asyncio.create_task(_every(300,       _evict_stalled_scans, "stall_eviction"))
    log.info("Scheduler started: BM25 rebuild (1h), eval (24h), eviction (5m)")
