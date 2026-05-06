"""
tests/unit/test_scanner.py — Unit tests for the scanner and risk scoring.
Run with: pytest tests/ -v
"""
import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock


# ── Scanner tests ──────────────────────────────────────────────────────────────
class TestScannerPatterns:
    """Tests for regex-based crypto primitive detection."""

    def test_rsa_detection(self):
        from services.scanner import _scan_directory
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "auth.py")
            with open(path, "w") as f:
                f.write("key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n")
            findings = _scan_directory(tmpdir)
            assert any(f["algorithm"] == "RSA" for f in findings), "RSA not detected"
            assert any(f["quantum_vulnerable"] for f in findings)

    def test_ecdsa_detection(self):
        from services.scanner import _scan_directory
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "sign.py")
            with open(path, "w") as f:
                f.write("from cryptography.hazmat.primitives.asymmetric import ec\nkey = ec.generate_private_key(ec.SECP256R1())\n")
            findings = _scan_directory(tmpdir)
            assert any(f["algorithm"] == "ECC" for f in findings)

    def test_md5_detection(self):
        from services.scanner import _scan_directory
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "util.py")
            with open(path, "w") as f:
                f.write("import hashlib\nhash = hashlib.md5(data).hexdigest()\n")
            findings = _scan_directory(tmpdir)
            assert any(f["algorithm"] == "MD5" for f in findings)

    def test_aes256_not_vulnerable(self):
        from services.scanner import QUANTUM_VULNERABLE
        assert "AES-256" not in QUANTUM_VULNERABLE

    def test_deduplication(self):
        from services.scanner import _deduplicate
        findings = [
            {"algorithm": "RSA", "location": "auth.py:10"},
            {"algorithm": "RSA", "location": "auth.py:10"},   # duplicate
            {"algorithm": "RSA", "location": "auth.py:20"},   # different line
        ]
        result = _deduplicate(findings)
        assert len(result) == 2


# ── HNDL scoring tests ─────────────────────────────────────────────────────────
class TestHndlScoring:

    def test_rsa_medical_high_score(self):
        from agents.qbom_graph import calculate_hndl_score
        score = calculate_hndl_score.invoke({
            "algorithm": "RSA-2048",
            "data_sensitivity": "medical",
            "exposure_years": 10
        })
        assert float(score) >= 6.0, f"RSA medical HNDL should be high, got {score}"

    def test_aes256_low_score(self):
        from agents.qbom_graph import calculate_hndl_score
        score = calculate_hndl_score.invoke({
            "algorithm": "AES-256",
            "data_sensitivity": "public",
            "exposure_years": 5
        })
        assert float(score) < 3.0, f"AES-256 public HNDL should be low, got {score}"

    def test_score_bounded(self):
        from agents.qbom_graph import calculate_hndl_score
        score = float(calculate_hndl_score.invoke({
            "algorithm": "RSA-2048",
            "data_sensitivity": "financial",
            "exposure_years": 20
        }))
        assert 0 <= score <= 10

    def test_migration_guidance_rsa(self):
        from agents.qbom_graph import get_migration_guidance
        result = json.loads(get_migration_guidance.invoke({"algorithm": "RSA-2048"}))
        assert "ML-KEM" in result["replace_with"]
        assert result["effort"] in ("low", "medium", "high")


# ── BOM generation tests ───────────────────────────────────────────────────────
class TestBomGeneration:

    def test_cyclonedx_structure(self):
        from services.bom_gen import generate_cyclonedx_bom
        findings = [
            {"algorithm": "RSA-2048", "location": "auth.py:10", "hndl_score": 8.5,
             "quantum_vulnerable": True, "is_shadow_crypto": False}
        ]
        bom = generate_cyclonedx_bom(findings, "https://github.com/test/repo", "test-scan-id")
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.7"
        assert len(bom["components"]) == 1
        assert bom["components"][0]["type"] == "cryptographic-asset"
        assert len(bom["vulnerabilities"]) == 1  # RSA is quantum-vulnerable

    def test_non_vulnerable_not_in_vulns(self):
        from services.bom_gen import generate_cyclonedx_bom
        findings = [
            {"algorithm": "AES-256", "location": "cipher.py:5", "hndl_score": 0.5,
             "quantum_vulnerable": False, "is_shadow_crypto": False}
        ]
        bom = generate_cyclonedx_bom(findings, "https://github.com/test/repo", "test-id-2")
        assert len(bom["vulnerabilities"]) == 0

    def test_report_markdown_contains_findings(self):
        from services.bom_gen import generate_report_markdown
        from unittest.mock import MagicMock
        from datetime import datetime
        scan = MagicMock()
        scan.target = "https://github.com/test/repo"
        scan.target_type = "repo"
        scan.id = "test-scan-123"
        scan.status = "complete"
        scan.hndl_score = 8.5
        scan.risk_level = "critical"
        scan.created_at = datetime(2025, 1, 1, 12, 0, 0)
        scan.agent_trace = {"reflection_iterations": 1, "reflection_passed": True, "message_count": 12}
        scan.findings = [
            {"algorithm": "RSA-2048", "location": "auth.py:42", "hndl_score": 8.5,
             "quantum_vulnerable": True, "is_shadow_crypto": False, "migration_path": "ML-KEM-768"}
        ]
        md = generate_report_markdown(scan)
        assert "RSA-2048" in md
        assert "ML-KEM-768" in md
        assert "8.5" in md
        assert "CycloneDX" not in md   # report is human-readable, not the BOM itself


# ── Hybrid retrieval tests ─────────────────────────────────────────────────────
class TestHybridRetrieval:

    def test_rrf_merges_results(self):
        from services.hybrid_retrieval import reciprocal_rank_fusion, RetrievedDoc
        bm25 = [
            RetrievedDoc("id1", "RSA", "RSA content", "NIST", 0.9, "bm25"),
            RetrievedDoc("id2", "ECC", "ECC content", "NIST", 0.7, "bm25"),
        ]
        dense = [
            RetrievedDoc("id2", "ECC", "ECC content", "NIST", 0.95, "dense"),
            RetrievedDoc("id3", "AES", "AES content", "NIST", 0.85, "dense"),
        ]
        result = reciprocal_rank_fusion(bm25, dense, top_k=3)
        assert len(result) <= 3
        # id2 (ECC) appears in both lists so should rank high
        ids = [r.id for r in result]
        assert "id2" in ids
        # All results should be labelled hybrid
        assert all(r.retrieval_method == "hybrid" for r in result)

    def test_rrf_scores_are_positive(self):
        from services.hybrid_retrieval import reciprocal_rank_fusion, RetrievedDoc
        bm25 = [RetrievedDoc(f"id{i}", "algo", "content", "src", float(i), "bm25") for i in range(5)]
        dense = [RetrievedDoc(f"id{i}", "algo", "content", "src", float(i), "dense") for i in range(3, 8)]
        result = reciprocal_rank_fusion(bm25, dense)
        assert all(r.score > 0 for r in result)


# ── Risk band tests ────────────────────────────────────────────────────────────
class TestRiskBands:
    def test_bands(self):
        from routers.risk import _risk_band
        assert _risk_band(9.0) == "critical"
        assert _risk_band(7.0) == "high"
        assert _risk_band(5.0) == "medium"
        assert _risk_band(3.0) == "low"
        assert _risk_band(1.0) == "minimal"
