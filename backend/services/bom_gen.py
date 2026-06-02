"""
services/bom_gen.py — CycloneDX v1.7 BOM generation and Markdown report builder.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from models.db import ScanRecord


RISK_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "minimal": "✅"}


def generate_cyclonedx_bom(findings: list[dict], target: str, scan_id: str) -> dict:
    """
    Build a CycloneDX v1.7 CBOM from enriched findings.
    v1.7 adds first-class cryptoProperties with quantumVulnerable field.
    """
    now = datetime.now(timezone.utc).isoformat()

    vuln_count = sum(1 for f in findings if f.get("quantum_vulnerable"))
    avg_hndl = sum(f.get("hndl_score", 0) for f in findings) / len(findings) if findings else 0
    max_hndl = max((f.get("hndl_score", 0) for f in findings), default=0)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "serialNumber": f"urn:uuid:{scan_id}",
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "Q-BOM AI",
                    "name": "Q-BOM AI Autonomous Scanner",
                    "version": "1.0.0",
                    "externalReferences": [
                        {"type": "website", "url": "https://qbom.ai"}
                    ]
                }
            ],
            "component": {
                "type": "application",
                "name": target.split("/")[-1] if "/" in target else target,
                "version": "unknown",
                "externalReferences": [
                    {"type": "vcs" if "github" in target else "website", "url": target}
                ]
            },
            "properties": [
                {"name": "qbom:scanId", "value": scan_id},
                {"name": "qbom:avgHndlScore", "value": str(round(avg_hndl, 2))},
                {"name": "qbom:maxHndlScore", "value": str(round(max_hndl, 2))},
                {"name": "qbom:quantumVulnerableCount", "value": str(vuln_count)},
                {"name": "qbom:totalFindings", "value": str(len(findings))},
            ]
        },
        "components": [
            _finding_to_component(f, i) for i, f in enumerate(findings) if isinstance(f, dict)
        ],
        "vulnerabilities": [
            _finding_to_vulnerability(f, scan_id) for f in findings
            if isinstance(f, dict) and f.get("quantum_vulnerable")
        ],
        "dependencies": [],
        "compositions": [
            {
                "aggregate": "incomplete",
                "assemblies": [f"crypto-{i}" for i in range(len(findings))]
            }
        ],
        "qbomMeta": {
            "avgHndlScore": round(avg_hndl, 2),
            "maxHndlScore": round(max_hndl, 2),
            "totalFindings": len(findings),
            "quantumVulnerableCount": vuln_count,
        }
    }
    return bom


def _finding_to_component(finding: dict, idx: int) -> dict:
    algo = finding.get("algorithm", "unknown")
    primitive = _infer_primitive(algo)
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto-{idx}",
        "name": algo,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": algo,
                "executionEnvironment": "application",
                "implementationPlatform": finding.get("platform", "unknown"),
                "certificationLevel": _get_cert_level(algo),
                "mode": _infer_mode(algo),
                "padding": "pkcs1v15" if "RSA" in algo.upper() else None,
                "cryptoFunctions": ["keygen", "sign"] if "DSA" in algo.upper() else ["encrypt", "decrypt"],
                "classicalSecurityLevel": _classical_security(algo),
                "nistQuantumSecurityLevel": _quantum_security_level(algo),
            },
            "oid": _get_oid(algo),
            "related": [],
        },
        "properties": [
            {"name": "qbom:hndlScore",       "value": str(finding.get("hndl_score", 0))},
            {"name": "qbom:location",         "value": finding.get("location", "")},
            {"name": "qbom:isShadowCrypto",   "value": str(finding.get("is_shadow_crypto", False))},
            {"name": "qbom:quantumVulnerable","value": str(finding.get("quantum_vulnerable", True))},
            {"name": "qbom:migrationPath",    "value": str(finding.get("migration_path") or "")},
            {"name": "qbom:source",           "value": finding.get("source", "scan")},
            {"name": "qbom:snippet",          "value": finding.get("snippet", "")[:200]},
        ],
        "evidence": {
            "occurrences": [{"location": finding.get("location", "")}]
        }
    }


def _finding_to_vulnerability(finding: dict, scan_id: str) -> dict:
    algo = finding.get("algorithm", "unknown")
    score = finding.get("hndl_score", 0)
    severity = "critical" if score >= 8 else "high" if score >= 6 else "medium" if score >= 4 else "low"
    return {
        "id": f"QBOM-{scan_id[:8]}-{algo.replace('-','').replace(' ','')}",
        "source": {"name": "Q-BOM AI", "url": "https://qbom.ai"},
        "description": f"{algo} is vulnerable to Shor's algorithm on a Cryptographically Relevant Quantum Computer (CRQC).",
        "detail": f"HNDL risk score: {score}/10. Migration: {finding.get('migration_path', 'See NIST PQC guidance')}",
        "ratings": [{
            "source": {"name": "Q-BOM HNDL Calculator"},
            "score": score,
            "severity": severity,
            "method": "HNDL",
            "justification": "Harvest-Now-Decrypt-Later threat model applied"
        }],
        "affects": [{"ref": f"crypto-{finding.get('_idx', 0)}"}],
        "recommendation": finding.get("migration_path") or "Migrate to NIST-standardised PQC algorithm",
    }


def _infer_primitive(algo: str) -> str:
    algo_up = algo.upper()
    if any(k in algo_up for k in ["RSA", "ECC", "ECDH", "DH", "ML-KEM"]): return "pke"
    if any(k in algo_up for k in ["DSA", "ECDSA", "ML-DSA", "SLH-DSA"]):  return "signature"
    if any(k in algo_up for k in ["AES", "3DES", "BLOWFISH", "RC4"]):     return "blockCipher"
    if any(k in algo_up for k in ["SHA", "MD5", "BLAKE"]):                 return "hash"
    if "HMAC" in algo_up:                                                   return "mac"
    return "unknown"


def _infer_mode(algo: str) -> str | None:
    if "GCM" in algo.upper(): return "gcm"
    if "CBC" in algo.upper(): return "cbc"
    if "CTR" in algo.upper(): return "ctr"
    return None


def _get_cert_level(algo: str) -> list[str]:
    fips_approved = {"AES-256", "SHA-256", "SHA-384", "SHA-512", "ML-KEM-768", "ML-DSA-65"}
    return ["FIPS140-2"] if algo in fips_approved else []


def _classical_security(algo: str) -> int:
    levels = {"RSA-2048": 112, "RSA-4096": 140, "ECDSA-256": 128, "AES-128": 128,
              "AES-256": 256, "SHA-256": 128, "SHA-512": 256, "MD5": 0, "SHA-1": 0}
    for k, v in levels.items():
        if k in algo.upper():
            return v
    return 128


def _quantum_security_level(algo: str) -> int:
    """NIST quantum security level (0 = vulnerable)."""
    pqc_levels = {"ML-KEM-768": 3, "ML-DSA-65": 3, "SLH-DSA-128s": 1, "AES-256": 3, "SHA-512": 3}
    for k, v in pqc_levels.items():
        if k in algo.upper():
            return v
    return 0  # quantum-vulnerable


def _get_oid(algo: str) -> str | None:
    oids = {
        "RSA": "1.2.840.113549.1.1.1",
        "ECDSA": "1.2.840.10045.4.3.2",
        "AES-128": "2.16.840.1.101.3.4.1.1",
        "AES-256": "2.16.840.1.101.3.4.1.41",
        "SHA-256": "2.16.840.1.101.3.4.2.1",
        "SHA-1": "1.3.14.3.2.26",
        "MD5": "1.2.840.113549.2.5",
    }
    for k, v in oids.items():
        if k in algo.upper():
            return v
    return None


# ── Markdown report ────────────────────────────────────────────────────────────
def generate_report_markdown(scan: "ScanRecord") -> str:
    """Generate a human-readable Markdown risk report from a completed scan."""
    findings = scan.findings or []
    if not isinstance(findings, list):
        findings = []

    vuln = [f for f in findings if isinstance(f, dict) and f.get("quantum_vulnerable")]
    shadow = [f for f in findings if isinstance(f, dict) and f.get("is_shadow_crypto")]
    scores = [f.get("hndl_score", 0) for f in findings if isinstance(f, dict)]
    avg_hndl = sum(scores) / len(scores) if scores else 0

    risk_emoji = RISK_EMOJI.get(scan.risk_level or "low", "❓")

    lines = [
        f"# Q-BOM AI Security Report",
        f"",
        f"**Target:** `{scan.target}`  ",
        f"**Type:** {scan.target_type}  ",
        f"**Scan ID:** `{scan.id}`  ",
        f"**Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M UTC') if scan.created_at else 'unknown'}",
        f"",
        f"## Executive Summary",
        f"",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Risk Level | {risk_emoji} **{(scan.risk_level or 'unknown').upper()}** |",
        f"| HNDL Score | {scan.hndl_score:.1f} / 10 |",
        f"| Total Findings | {len(findings)} |",
        f"| Quantum-Vulnerable | {len(vuln)} |",
        f"| Shadow Crypto | {len(shadow)} |",
        f"| Avg HNDL | {avg_hndl:.2f} |",
        f"",
        f"## Critical Findings",
        f"",
    ]

    critical = sorted(
        [f for f in findings if isinstance(f, dict) and f.get("hndl_score", 0) >= 6],
        key=lambda x: x.get("hndl_score", 0), reverse=True
    )

    for f in critical[:10]:
        score = f.get("hndl_score", 0)
        emoji = "🔴" if score >= 8 else "🟠"
        lines += [
            f"### {emoji} {f.get('algorithm', 'unknown')} — HNDL {score:.1f}",
            f"",
            f"- **Location:** `{f.get('location', '—')}`",
            f"- **Quantum Vulnerable:** {'Yes' if f.get('quantum_vulnerable') else 'No'}",
            f"- **Shadow Crypto:** {'Yes ⚠️' if f.get('is_shadow_crypto') else 'No'}",
            f"- **Migration:** {f.get('migration_path', '—')}",
            f"- **Snippet:** `{f.get('snippet', '—')[:80]}`",
            f"",
        ]

    lines += [
        f"## Migration Roadmap",
        f"",
        f"| Priority | Algorithm | Replace With | CNSA 2.0 Deadline |",
        f"|----------|-----------|--------------|-------------------|",
    ]

    MIGRATIONS = {
        "RSA": ("ML-KEM-768 (FIPS 203)", "2030"),
        "ECDSA": ("ML-DSA-65 (FIPS 204)", "2030"),
        "ECDH": ("ML-KEM-768 (FIPS 203)", "2030"),
        "DH": ("ML-KEM-768 (FIPS 203)", "2028"),
        "SHA-1": ("SHA-3-256", "Immediate"),
        "MD5": ("SHA-256", "Immediate"),
        "AES-128": ("AES-256", "2025"),
        "3DES": ("AES-256-GCM", "2024"),
    }

    seen_algos = set()
    for f in critical:
        algo = f.get("algorithm", "")
        for key, (replacement, deadline) in MIGRATIONS.items():
            if key in algo.upper() and key not in seen_algos:
                seen_algos.add(key)
                priority = "P1" if f.get("hndl_score", 0) >= 8 else "P2"
                lines.append(f"| {priority} | {algo} | {replacement} | {deadline} |")

    lines += [
        f"",
        f"## Agent Trace Summary",
        f"",
        f"- **Reflection iterations:** {(scan.agent_trace or {}).get('reflection_iterations', 0)}",
        f"- **Reflection passed:** {(scan.agent_trace or {}).get('reflection_passed', False)}",
        f"- **Messages processed:** {(scan.agent_trace or {}).get('message_count', 0)}",
        f"",
        f"---",
        f"*Generated by Q-BOM AI v1.0.0 — [qbom.ai](https://qbom.ai)*",
    ]

    return "\n".join(lines)
