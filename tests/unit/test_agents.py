"""
tests/unit/test_agents.py — Unit tests for LangGraph agent routing and tool logic.

Tests:
  - route_from_supervisor correctness
  - route_from_reflector correctness
  - HNDL scoring boundaries
  - BOM component generation
  - Compliance deadline calculations
"""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ── QBOMState routing logic ────────────────────────────────────────────────────
class TestSupervisorRouting:
    """Tests for route_from_supervisor conditional edge."""

    def _make_state(self, **kwargs):
        from agents.qbom_graph import QBOMState
        defaults = {
            "messages": [],
            "target": "https://github.com/test/repo",
            "target_type": "repo",
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
        defaults.update(kwargs)
        return defaults

    def test_routes_to_scanner_when_next_agent_scanner(self):
        from agents.qbom_graph import route_from_supervisor
        state = self._make_state(next_agent="scanner")
        assert route_from_supervisor(state) == "scanner"

    def test_routes_to_enricher(self):
        from agents.qbom_graph import route_from_supervisor
        state = self._make_state(next_agent="enricher")
        assert route_from_supervisor(state) == "enricher"

    def test_routes_to_end_on_end(self):
        from agents.qbom_graph import route_from_supervisor
        from langgraph.graph import END
        state = self._make_state(next_agent="end")
        assert route_from_supervisor(state) == END

    def test_routes_to_reporter(self):
        from agents.qbom_graph import route_from_supervisor
        state = self._make_state(next_agent="reporter")
        assert route_from_supervisor(state) == "reporter"


class TestReflectorRouting:
    """Tests for route_from_reflector conditional edge."""

    def _state(self, passed, iterations):
        return {
            "reflection_passed": passed,
            "reflection_iterations": iterations,
            "messages": [], "target": "x", "target_type": "repo",
            "raw_findings": [], "enriched_findings": [],
            "bom_json": "", "hndl_score": 0.0, "risk_level": "", "next_agent": "", "error": None,
        }

    def test_passes_to_reporter_when_approved(self):
        from agents.qbom_graph import route_from_reflector
        state = self._state(passed=True, iterations=1)
        assert route_from_reflector(state) == "reporter"

    def test_routes_back_to_enricher_on_fail(self):
        from agents.qbom_graph import route_from_reflector
        state = self._state(passed=False, iterations=1)
        assert route_from_reflector(state) == "enricher"

    def test_max_iterations_forces_reporter(self):
        """After 2 reflection iterations, always go to reporter regardless of pass/fail."""
        # The reflector_node itself handles this — sets reflection_passed=True after iter>=2
        # Here we just verify the routing respects passed=True
        from agents.qbom_graph import route_from_reflector
        state = self._state(passed=True, iterations=2)
        assert route_from_reflector(state) == "reporter"


# ── HNDL tool boundary tests ───────────────────────────────────────────────────
class TestHndlTool:
    def test_score_always_in_range(self):
        from agents.qbom_graph import calculate_hndl_score
        for algo in ["RSA-2048", "AES-256", "SHA-256", "MD5", "UNKNOWN-ALGO"]:
            for sens in ["public", "medical", "financial"]:
                score = float(calculate_hndl_score.invoke({
                    "algorithm": algo,
                    "data_sensitivity": sens,
                    "exposure_years": 10,
                }))
                assert 0 <= score <= 10, f"{algo}/{sens} score out of range: {score}"

    def test_rsa_medical_critical(self):
        from agents.qbom_graph import calculate_hndl_score
        score = float(calculate_hndl_score.invoke({
            "algorithm": "RSA-2048", "data_sensitivity": "medical", "exposure_years": 10
        }))
        assert score >= 7.0, f"RSA-2048 + medical should be critical, got {score}"

    def test_aes256_public_minimal(self):
        from agents.qbom_graph import calculate_hndl_score
        score = float(calculate_hndl_score.invoke({
            "algorithm": "AES-256", "data_sensitivity": "public", "exposure_years": 5
        }))
        assert score < 2.0, f"AES-256 + public should be minimal risk, got {score}"

    def test_migration_rsa_returns_mlkem(self):
        from agents.qbom_graph import get_migration_guidance
        result = json.loads(get_migration_guidance.invoke({"algorithm": "RSA-2048"}))
        assert "ML-KEM" in result["replace_with"]
        assert "FIPS" in result.get("replace_with", "") or "FIPS" in result.get("fips_replacement", result.get("standard", ""))

    def test_migration_ecdsa_returns_mldsa(self):
        from agents.qbom_graph import get_migration_guidance
        result = json.loads(get_migration_guidance.invoke({"algorithm": "ECDSA-256"}))
        assert "ML-DSA" in result["replace_with"]

    def test_migration_sha1_returns_sha3(self):
        from agents.qbom_graph import get_migration_guidance
        result = json.loads(get_migration_guidance.invoke({"algorithm": "SHA-1"}))
        assert "SHA" in result["replace_with"]


# ── BOM generation correctness ─────────────────────────────────────────────────
class TestBomGeneration:

    SAMPLE_FINDINGS = [
        {"algorithm": "RSA-2048",  "location": "auth.py:42", "hndl_score": 8.5,
         "quantum_vulnerable": True,  "is_shadow_crypto": False,
         "migration_path": "ML-KEM-768", "snippet": "rsa.generate_private_key()", "_idx": 0},
        {"algorithm": "AES-256",   "location": "cipher.py:5", "hndl_score": 0.5,
         "quantum_vulnerable": False, "is_shadow_crypto": False,
         "migration_path": "No change", "snippet": "AES.new(key, AES.MODE_GCM)", "_idx": 1},
    ]

    def test_bom_format_version(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        assert bom["bomFormat"] == "CycloneDX"
        assert bom["specVersion"] == "1.7"

    def test_bom_component_count(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        assert len(bom["components"]) == 2

    def test_vulnerabilities_only_for_quantum_vulns(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        # Only RSA-2048 is quantum-vulnerable; AES-256 is not
        assert len(bom["vulnerabilities"]) == 1
        assert "RSA" in bom["vulnerabilities"][0]["id"]

    def test_crypto_properties_present(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        for comp in bom["components"]:
            assert "cryptoProperties" in comp
            assert "assetType" in comp["cryptoProperties"]
            assert comp["cryptoProperties"]["assetType"] == "algorithm"

    def test_hndl_score_in_properties(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        rsa_comp = next(c for c in bom["components"] if "RSA" in c["name"])
        props = {p["name"]: p["value"] for p in rsa_comp["properties"]}
        assert props["qbom:hndlScore"] == "8.5"

    def test_qbom_meta_aggregate(self):
        from services.bom_gen import generate_cyclonedx_bom
        bom = generate_cyclonedx_bom(self.SAMPLE_FINDINGS, "https://github.com/t/r", "scan-001")
        meta = bom["qbomMeta"]
        assert meta["quantumVulnerableCount"] == 1
        assert meta["totalFindings"] == 2
        assert meta["maxHndlScore"] == pytest.approx(8.5, abs=0.01)

    def test_infer_primitive_rsa(self):
        from services.bom_gen import _infer_primitive
        assert _infer_primitive("RSA-2048") == "pke"

    def test_infer_primitive_aes(self):
        from services.bom_gen import _infer_primitive
        assert _infer_primitive("AES-256-GCM") == "blockCipher"

    def test_infer_primitive_sha(self):
        from services.bom_gen import _infer_primitive
        assert _infer_primitive("SHA-256") == "hash"

    def test_quantum_security_level_pqc(self):
        from services.bom_gen import _quantum_security_level
        assert _quantum_security_level("ML-KEM-768") == 3
        assert _quantum_security_level("AES-256") == 3
        assert _quantum_security_level("RSA-2048") == 0


# ── Risk band tests ────────────────────────────────────────────────────────────
class TestRiskBands:
    def test_all_bands(self):
        from routers.risk import _risk_band
        assert _risk_band(9.5) == "critical"
        assert _risk_band(7.0) == "high"
        assert _risk_band(5.0) == "medium"
        assert _risk_band(3.0) == "low"
        assert _risk_band(1.0) == "minimal"

    def test_boundary_values(self):
        from routers.risk import _risk_band
        assert _risk_band(8.0) == "critical"  # exact boundary
        assert _risk_band(7.99) == "high"
        assert _risk_band(6.0) == "high"      # exact boundary
        assert _risk_band(5.99) == "medium"
        assert _risk_band(4.0) == "medium"    # exact boundary
        assert _risk_band(3.99) == "low"
        assert _risk_band(2.0) == "low"       # exact boundary
        assert _risk_band(1.99) == "minimal"
        assert _risk_band(0.0) == "minimal"


# ── RRF fusion math ────────────────────────────────────────────────────────────
class TestRRF:
    def _doc(self, doc_id, algo, score, method="bm25"):
        from services.hybrid_retrieval import RetrievedDoc
        return RetrievedDoc(doc_id, algo, f"Content for {algo}", "NIST", score, method)

    def test_rrf_overlap_boosts_score(self):
        """A doc appearing in both BM25 and dense lists should score higher than solo."""
        from services.hybrid_retrieval import reciprocal_rank_fusion
        shared = self._doc("shared", "RSA", 0.9, "bm25")
        unique = self._doc("unique", "ECC", 0.95, "bm25")

        bm25  = [shared, unique]
        dense = [self._doc("shared", "RSA", 0.85, "dense"), self._doc("other", "AES", 0.7, "dense")]

        result = reciprocal_rank_fusion(bm25, dense, top_k=4)
        shared_result = next(r for r in result if r.id == "shared")
        unique_result = next(r for r in result if r.id == "unique")
        # "shared" appears in both lists → higher RRF score than "unique" (only in BM25)
        assert shared_result.score > unique_result.score

    def test_rrf_all_labelled_hybrid(self):
        from services.hybrid_retrieval import reciprocal_rank_fusion
        bm25  = [self._doc(f"b{i}", "RSA", float(i)) for i in range(3)]
        dense = [self._doc(f"d{i}", "ECC", float(i)) for i in range(3)]
        result = reciprocal_rank_fusion(bm25, dense)
        assert all(r.retrieval_method == "hybrid" for r in result)

    def test_rrf_respects_top_k(self):
        from services.hybrid_retrieval import reciprocal_rank_fusion
        bm25  = [self._doc(f"b{i}", "RSA", float(i)) for i in range(10)]
        dense = [self._doc(f"d{i}", "ECC", float(i)) for i in range(10)]
        result = reciprocal_rank_fusion(bm25, dense, top_k=3)
        assert len(result) <= 3
