"""
routers/risk.py — Risk analytics endpoints.

Endpoints:
  GET  /api/risk/{scan_id}/hndl         — Detailed HNDL breakdown
  GET  /api/risk/{scan_id}/compliance   — CNSA 2.0 / FIPS compliance status
  GET  /api/risk/project/{name}         — Aggregated project risk metrics
  POST /api/risk/score                  — Ad-hoc HNDL score calculator
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from models.db import get_db, ScanRecord
from agents.qbom_graph import calculate_hndl_score

router = APIRouter(prefix="/api/risk", tags=["risk"])

# ── CNSA 2.0 compliance rules ──────────────────────────────────────────────────
CNSA2_RULES = {
    "RSA":    {"allowed_until": 2030, "replacement": "ML-KEM-768", "standard": "FIPS 203"},
    "ECDSA":  {"allowed_until": 2030, "replacement": "ML-DSA-65",  "standard": "FIPS 204"},
    "ECDH":   {"allowed_until": 2030, "replacement": "ML-KEM-768", "standard": "FIPS 203"},
    "DH":     {"allowed_until": 2028, "replacement": "ML-KEM-768", "standard": "FIPS 203"},
    "DSA":    {"allowed_until": 2025, "replacement": "ML-DSA-65",  "standard": "FIPS 204"},
    "SHA-1":  {"allowed_until": 2025, "replacement": "SHA-3-256",  "standard": "FIPS 202"},
    "MD5":    {"allowed_until": 2023, "replacement": "SHA-256",    "standard": "FIPS 180-4"},
    "3DES":   {"allowed_until": 2024, "replacement": "AES-256",    "standard": "FIPS 197"},
    "AES-128":{"allowed_until": 2030, "replacement": "AES-256",    "standard": "FIPS 197"},
}

CURRENT_YEAR = 2026


class HndlScoreRequest(BaseModel):
    algorithm: str
    data_sensitivity: str = "medium"
    exposure_years: int = 10


@router.get("/{scan_id}/hndl")
async def get_hndl_breakdown(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return per-algorithm HNDL breakdown for a completed scan."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or scan.status != "complete":
        raise HTTPException(status_code=404, detail="Scan not found or not complete")

    findings = scan.findings or []
    if not isinstance(findings, list):
        raise HTTPException(status_code=500, detail="Invalid findings format")

    breakdown = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        algo = f.get("algorithm", "unknown")
        score = f.get("hndl_score", 0)
        breakdown.append({
            "algorithm": algo,
            "location": f.get("location", ""),
            "hndl_score": score,
            "risk_band": _risk_band(score),
            "quantum_vulnerable": f.get("quantum_vulnerable", False),
            "is_shadow_crypto": f.get("is_shadow_crypto", False),
            "data_sensitivity": f.get("data_sensitivity", "medium"),
            "crqc_deadline": "2030–2035",
            "migration": f.get("migration_path") or f.get("migration", {}).get("replace_with", "—"),
        })

    # Sort by HNDL score descending
    breakdown.sort(key=lambda x: x["hndl_score"], reverse=True)

    scores = [b["hndl_score"] for b in breakdown]
    return {
        "scan_id": scan_id,
        "target": scan.target,
        "aggregate": {
            "max": max(scores) if scores else 0,
            "avg": round(sum(scores) / len(scores), 2) if scores else 0,
            "critical_count": sum(1 for s in scores if s >= 8),
            "high_count": sum(1 for s in scores if 6 <= s < 8),
            "medium_count": sum(1 for s in scores if 4 <= s < 6),
            "low_count": sum(1 for s in scores if s < 4),
        },
        "breakdown": breakdown,
    }


@router.get("/{scan_id}/compliance")
async def get_compliance(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Check findings against CNSA 2.0 and NIST FIPS deadlines."""
    result = await db.execute(select(ScanRecord).where(ScanRecord.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or scan.status != "complete":
        raise HTTPException(status_code=404, detail="Scan not found or not complete")

    findings = scan.findings or []
    compliance_items = []
    overdue = 0
    urgent = 0
    planned = 0

    for f in findings:
        if not isinstance(f, dict):
            continue
        algo = f.get("algorithm", "")
        rule = None
        for key, val in CNSA2_RULES.items():
            if key in algo.upper():
                rule = val
                break

        if rule:
            years_left = rule["allowed_until"] - CURRENT_YEAR
            if years_left < 0:
                status = "overdue"
                overdue += 1
            elif years_left <= 2:
                status = "urgent"
                urgent += 1
            else:
                status = "planned"
                planned += 1

            compliance_items.append({
                "algorithm": algo,
                "location": f.get("location", ""),
                "cnsa2_deadline": rule["allowed_until"],
                "years_remaining": years_left,
                "replacement": rule["replacement"],
                "fips_standard": rule["standard"],
                "status": status,
            })

    compliance_items.sort(key=lambda x: x["years_remaining"])

    return {
        "scan_id": scan_id,
        "target": scan.target,
        "summary": {
            "overdue": overdue,
            "urgent": urgent,
            "planned": planned,
            "compliant": len([f for f in findings if isinstance(f, dict) and not f.get("quantum_vulnerable")]),
        },
        "overall_status": "overdue" if overdue > 0 else ("urgent" if urgent > 0 else "compliant"),
        "items": compliance_items,
    }


@router.get("/project/{project_name}")
async def get_project_risk(project_name: str, db: AsyncSession = Depends(get_db)):
    """Aggregate risk metrics across all scans matching a project name."""
    result = await db.execute(
        select(ScanRecord)
        .where(ScanRecord.target.ilike(f"%{project_name}%"))
        .where(ScanRecord.status == "complete")
        .order_by(ScanRecord.created_at.desc())
        .limit(50)
    )
    scans = result.scalars().all()

    if not scans:
        raise HTTPException(status_code=404, detail=f"No scans found for project: {project_name}")

    hndl_scores = [s.hndl_score for s in scans if s.hndl_score is not None]
    all_findings = []
    for s in scans:
        if isinstance(s.findings, list):
            all_findings.extend(s.findings)

    return {
        "project": project_name,
        "scan_count": len(scans),
        "avg_hndl": round(sum(hndl_scores) / len(hndl_scores), 2) if hndl_scores else 0,
        "max_hndl": max(hndl_scores) if hndl_scores else 0,
        "total_findings": len(all_findings),
        "quantum_vulnerable": sum(1 for f in all_findings if isinstance(f, dict) and f.get("quantum_vulnerable")),
        "shadow_crypto": sum(1 for f in all_findings if isinstance(f, dict) and f.get("is_shadow_crypto")),
        "risk_trend": [{"scan_id": s.id[:8], "hndl": s.hndl_score, "risk": s.risk_level} for s in scans[:10]],
    }


@router.post("/score")
async def calculate_score(req: HndlScoreRequest):
    """Ad-hoc HNDL risk calculator — no scan required."""
    score = calculate_hndl_score.invoke({
        "algorithm": req.algorithm,
        "data_sensitivity": req.data_sensitivity,
        "exposure_years": req.exposure_years
    })
    return {
        "algorithm": req.algorithm,
        "data_sensitivity": req.data_sensitivity,
        "exposure_years": req.exposure_years,
        "hndl_score": score,
        "risk_band": _risk_band(float(score)),
        "crqc_window": "2030–2035",
    }


def _risk_band(score: float) -> str:
    if score >= 8:   return "critical"
    if score >= 6:   return "high"
    if score >= 4:   return "medium"
    if score >= 2:   return "low"
    return "minimal"
