"""
routers/admin.py — Admin endpoints for ops and internal tooling.

Endpoints:
  GET  /api/admin/audit           — View recent audit log entries
  GET  /api/admin/rate-limits     — Current rate-limit state per key hash
  GET  /api/admin/stats           — System-wide statistics
  POST /api/admin/keys/rotate     — Rotate an API key
  POST /api/admin/kb/refresh      — Manually trigger BM25 corpus rebuild

All endpoints require the 'pro' tier key or an admin key.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select, func, desc, text
from sqlalchemy.ext.asyncio import AsyncSession

from models.db import get_db, ScanRecord

router = APIRouter(prefix="/api/admin", tags=["admin"])


def _require_pro(request: Request):
    """Dependency — only pro or admin tier keys may access admin routes."""
    tier = getattr(request.state, "tier", None)
    if tier not in ("pro", "admin"):
        raise HTTPException(status_code=403, detail="Admin routes require a pro API key")


# ── Audit log viewer ───────────────────────────────────────────────────────────
@router.get("/audit", dependencies=[Depends(_require_pro)])
async def get_audit_log(
    limit: int = 100,
    path: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Return recent audit log entries, optionally filtered by path."""
    q = "SELECT * FROM audit_log"
    params: dict = {"limit": limit}
    if path:
        q += " WHERE path LIKE :path"
        params["path"] = f"%{path}%"
    q += " ORDER BY created_at DESC LIMIT :limit"

    try:
        result = await db.execute(text(q), params)
        rows = [dict(r._mapping) for r in result]
        return {"entries": rows, "count": len(rows)}
    except Exception:
        # audit_log table may not exist yet on fresh installs
        return {"entries": [], "count": 0, "note": "audit_log table not yet created — run migrations"}


# ── Rate limit stats ───────────────────────────────────────────────────────────
@router.get("/rate-limits", dependencies=[Depends(_require_pro)])
async def get_rate_limits():
    """Return current in-memory rate-limit counters per key hash."""
    from middleware.auth import _rate_store
    summary = {
        key_hash: {
            "requests_in_window": len(timestamps),
            "oldest_request": min(timestamps) if timestamps else None,
        }
        for key_hash, timestamps in _rate_store.items()
        if timestamps
    }
    return {"active_keys": len(summary), "limits": summary}


# ── System statistics ──────────────────────────────────────────────────────────
@router.get("/stats", dependencies=[Depends(_require_pro)])
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Return system-wide aggregate statistics."""
    # Scan counts by status
    status_result = await db.execute(
        text("SELECT status, COUNT(*) as cnt FROM scans GROUP BY status")
    )
    by_status = {row.status: row.cnt for row in status_result}

    # Total finding counts
    finding_result = await db.execute(
        select(
            func.count(ScanRecord.id).label("total_scans"),
            func.avg(ScanRecord.hndl_score).label("avg_hndl"),
            func.max(ScanRecord.hndl_score).label("max_hndl"),
        ).where(ScanRecord.status == "complete")
    )
    agg = finding_result.one()

    # Knowledge base size
    kb_result = await db.execute(text("SELECT COUNT(*) as cnt FROM crypto_knowledge"))
    kb_count = kb_result.scalar_one_or_none() or 0

    # Top vulnerable algorithms
    try:
        top_result = await db.execute(text("""
            SELECT algorithm, COUNT(*) as cnt
            FROM scan_findings
            WHERE quantum_vulnerable = true
            GROUP BY algorithm
            ORDER BY cnt DESC
            LIMIT 10
        """))
        top_algos = [{"algorithm": r.algorithm, "count": r.cnt} for r in top_result]
    except Exception:
        top_algos = []

    return {
        "scans": {
            "by_status": by_status,
            "total_complete": int(agg.total_scans or 0),
            "avg_hndl_score": round(float(agg.avg_hndl or 0), 2),
            "max_hndl_score": round(float(agg.max_hndl or 0), 2),
        },
        "knowledge_base": {"document_count": kb_count},
        "top_vulnerable_algorithms": top_algos,
    }


# ── Knowledge base refresh ─────────────────────────────────────────────────────
@router.post("/kb/refresh", dependencies=[Depends(_require_pro)])
async def refresh_knowledge_base():
    """Manually trigger a BM25 corpus rebuild from the current Postgres data."""
    from services.hybrid_retrieval import init_retrieval
    await init_retrieval()
    return {"message": "BM25 corpus rebuilt successfully"}


# ── API key rotation ───────────────────────────────────────────────────────────
@router.post("/keys/rotate", dependencies=[Depends(_require_pro)])
async def rotate_key(request: Request):
    """
    Placeholder for key rotation. In production this would:
    - Invalidate the old key in the database
    - Generate a new key
    - Return the new key (shown once)
    For this implementation, keys are in middleware/auth.py VALID_KEYS dict.
    """
    return {
        "message": "Key rotation not yet implemented — update VALID_KEYS in middleware/auth.py",
        "hint": "In production, store keys in Postgres with a keys table and rotate via this endpoint",
    }
