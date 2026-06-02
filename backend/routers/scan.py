"""
routers/scan.py — All scan-related endpoints.

Endpoints:
  POST   /api/scan                 — Enqueue a new scan
  GET    /api/scan/{id}            — Poll scan status
  GET    /api/scan/{id}/findings   — Get enriched findings
  GET    /api/scan/{id}/bom        — Download CycloneDX v1.7 BOM
  GET    /api/scan/{id}/report     — Human-readable risk report
  DELETE /api/scan/{id}            — Cancel / delete scan
  GET    /api/scans                — List all scans (paginated)
  WS     /api/scan/{id}/stream     — Real-time agent log streaming
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from models.db import get_db, ScanRecord, AsyncSessionLocal
from agents.qbom_graph import run_scan
from services.bom_gen import generate_report_markdown

router = APIRouter(prefix="/api/scan", tags=["scans"])

# ── Active WebSocket connections per scan_id ───────────────────────────────────
_ws_connections: dict[str, list[WebSocket]] = {}

# ── Pydantic models ────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    target_type: str = "repo"           # "repo" | "website"
    data_sensitivity: str = "medium"    # low|medium|high|critical|medical|financial
    branch: Optional[str] = "main"
    include_containers: bool = False

    @field_validator("target_type")
    @classmethod
    def validate_type(cls, v):
        if v not in ("repo", "website"):
            raise ValueError("target_type must be 'repo' or 'website'")
        return v

    @field_validator("data_sensitivity")
    @classmethod
    def validate_sensitivity(cls, v):
        valid = ("low", "medium", "high", "critical", "medical", "financial")
        if v not in valid:
            raise ValueError(f"data_sensitivity must be one of {valid}")
        return v


class ScanListResponse(BaseModel):
    scans: list[dict]
    total: int
    page: int
    page_size: int


# ── Background task ────────────────────────────────────────────────────────────
async def _execute_scan(scan_id: str, req: ScanRequest):
    """
    Runs the full LangGraph multi-agent pipeline in the background.
    Streams progress events to any connected WebSocket clients.
    """
    async def emit(msg: str, level: str = "info"):
        payload = json.dumps({"type": "log", "level": level, "message": msg, "scan_id": scan_id})
        for ws in _ws_connections.get(scan_id, []):
            try:
                await ws.send_text(payload)
            except Exception:
                pass

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
        scan = result.scalar_one_or_none()
        if not scan:
            return

        try:
            scan.status = "scanning"
            await db.commit()
            await emit("LangGraph Supervisor initialising…")
            await emit(f"Target: {req.target} ({req.target_type})")

            await emit("Scanner Agent: beginning discovery phase…")
            await asyncio.sleep(0.5)  # allow WS to flush

            final_state = await run_scan(req.target, req.target_type)

            await emit(f"Scanner Agent: {len(final_state.get('raw_findings', []))} raw findings", "ok")
            await emit(f"Enricher Agent: running hybrid retrieval + tool-calling…")
            await emit(f"Reflector Agent: quality check — iterations: {final_state.get('reflection_iterations', 0)}", 
                       "ok" if final_state.get("reflection_passed") else "warn")
            await emit("Reporter Agent: generating CycloneDX v1.7 BOM…")

            scan.status = "complete"
            scan.findings = final_state.get("enriched_findings", [])
            scan.cyclonedx_bom = json.loads(final_state.get("bom_json", "{}"))
            scan.hndl_score = final_state.get("hndl_score", 0.0)
            scan.risk_level = final_state.get("risk_level", "unknown")
            scan.agent_trace = {
                "reflection_iterations": final_state.get("reflection_iterations", 0),
                "reflection_passed": final_state.get("reflection_passed", False),
                "message_count": len(final_state.get("messages", [])),
                "next_agent": final_state.get("next_agent", "end"),
            }
            await db.commit()

            # Save individual findings to scan_findings table
            from models.db import ScanFinding
            for f in (scan.findings or []):
                quantum_vulnerable = f.get("quantum_vulnerable", False)
                if isinstance(quantum_vulnerable, str):
                    quantum_vulnerable = quantum_vulnerable.lower() == "true"

                finding = ScanFinding(
                    scan_id=scan_id,
                    algorithm=f.get("algorithm", "unknown"),
                    location=f.get("location", "unknown"),
                    hndl_score=float(f.get("hndl_score", 0.0)),
                    is_shadow_crypto=bool(f.get("is_shadow_crypto", False)),
                    quantum_vulnerable=bool(quantum_vulnerable),
                )
                db.add(finding)
            await db.commit()

            # Record OTel metrics for the completed scan
            from observability.telemetry import record_scan_metrics
            record_scan_metrics(
                scan_id=scan_id,
                target=req.target,
                finding_count=len(scan.findings or []),
                hndl_score=scan.hndl_score or 0.0,
                duration_ms=0,  # duration tracked by OTel middleware
            )

            await emit(
                f"✓ Complete — {len(scan.findings or [])} findings, HNDL: {scan.hndl_score:.1f}, risk: {scan.risk_level}",
                "ok"
            )

            # Notify WS clients scan is done
            done_payload = json.dumps({
                "type": "complete",
                "scan_id": scan_id,
                "finding_count": len(scan.findings or []),
                "hndl_score": scan.hndl_score,
                "risk_level": scan.risk_level,
            })
            for ws in _ws_connections.get(scan_id, []):
                try:
                    await ws.send_text(done_payload)
                except Exception:
                    pass

        except Exception as e:
            scan.status = "failed"
            scan.findings = {"error": str(e)}
            await db.commit()
            await emit(f"Pipeline failed: {e}", "error")


# ── Routes ─────────────────────────────────────────────────────────────────────
@router.post("", status_code=202)
async def create_scan(req: ScanRequest, bg: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Enqueue a new scan. Returns scan_id immediately — poll GET /api/scan/{id} for status."""
    scan_id = str(uuid.uuid4())
    scan = ScanRecord(
        id=scan_id,
        target=req.target,
        target_type=req.target_type,
        status="queued",
        data_sensitivity=req.data_sensitivity,
    )
    db.add(scan)
    await db.commit()
    bg.add_task(_execute_scan, scan_id, req)
    return {"scan_id": scan_id, "status": "queued", "target": req.target}


@router.get("s")
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all scans with pagination and optional status filter."""
    query = select(ScanRecord).order_by(desc(ScanRecord.created_at))
    if status:
        query = query.where(ScanRecord.status == status)

    count_result = await db.execute(query)
    total = len(count_result.scalars().all())

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        scans=[{
            "scan_id": s.id,
            "target": s.target,
            "target_type": s.target_type,
            "status": s.status,
            "hndl_score": s.hndl_score,
            "risk_level": s.risk_level,
            "finding_count": len(s.findings or []) if isinstance(s.findings, list) else 0,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        } for s in scans],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{scan_id}")
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Poll scan status and summary metrics."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "scan_id": scan.id,
        "target": scan.target,
        "target_type": scan.target_type,
        "status": scan.status,
        "hndl_score": scan.hndl_score,
        "risk_level": scan.risk_level,
        "finding_count": len(scan.findings or []) if isinstance(scan.findings, list) else 0,
        "agent_trace": scan.agent_trace,
        "eval_scores": scan.eval_scores,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "updated_at": scan.updated_at.isoformat() if scan.updated_at else None,
    }


@router.get("/{scan_id}/findings")
async def get_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return the full enriched findings list."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in ("complete", "failed"):
        raise HTTPException(status_code=202, detail=f"Scan status: {scan.status}")
    if scan.status == "failed":
        raise HTTPException(status_code=500, detail=scan.findings)
    return {"scan_id": scan_id, "findings": scan.findings, "total": len(scan.findings or [])}


@router.get("/{scan_id}/bom")
async def get_bom(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Download the CycloneDX v1.7 CBOM JSON."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != "complete":
        raise HTTPException(status_code=202, detail="Scan not complete")
    return JSONResponse(
        content=scan.cyclonedx_bom,
        headers={"Content-Disposition": f'attachment; filename="qbom-{scan_id[:8]}.cdx.json"'}
    )


@router.get("/{scan_id}/report")
async def get_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Human-readable Markdown risk report."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or scan.status != "complete":
        raise HTTPException(status_code=404, detail="Scan not found or not complete")
    md = generate_report_markdown(scan)
    return JSONResponse(
        content={"report": md, "scan_id": scan_id},
        headers={"Content-Type": "application/json"}
    )


@router.delete("/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a scan record."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.delete(scan)
    await db.commit()


# ── WebSocket live stream ──────────────────────────────────────────────────────
@router.websocket("/{scan_id}/stream")
async def stream_scan(scan_id: str, websocket: WebSocket):
    """
    Real-time agent log streaming over WebSocket.
    The frontend connects here immediately after POST /api/scan.
    Agent nodes push log messages via the _ws_connections dict.
    """
    await websocket.accept()
    _ws_connections.setdefault(scan_id, []).append(websocket)
    try:
        while True:
            # Keep alive — wait for client ping or disconnect
            data = await asyncio.wait_for(websocket.receive_text(), timeout=60)
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        _ws_connections.get(scan_id, []).remove(websocket)
        if not _ws_connections.get(scan_id):
            _ws_connections.pop(scan_id, None)
