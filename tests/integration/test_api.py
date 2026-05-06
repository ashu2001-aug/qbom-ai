"""
tests/integration/test_api.py — Integration tests for the FastAPI endpoints.
Run with: pytest tests/integration/ -v --asyncio-mode=auto

Requires a running Postgres database (set DATABASE_URL in .env).
Uses httpx.AsyncClient to test endpoints end-to-end.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from main import app

API_KEY = "qbom-demo-key-2025"
HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers=HEADERS,
    ) as c:
        yield c


# ── Health ─────────────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_health(client: AsyncClient):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


# ── Scan lifecycle ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_create_scan_returns_202(client: AsyncClient):
    resp = await client.post("/api/scan", json={
        "target": "https://github.com/psf/requests",
        "target_type": "repo",
        "data_sensitivity": "medium"
    })
    assert resp.status_code == 202
    data = resp.json()
    assert "scan_id" in data
    assert data["status"] == "queued"


@pytest.mark.anyio
async def test_get_nonexistent_scan_404(client: AsyncClient):
    resp = await client.get("/api/scan/nonexistent-id")
    assert resp.status_code == 404


@pytest.mark.anyio
async def test_scan_validation_bad_type(client: AsyncClient):
    resp = await client.post("/api/scan", json={
        "target": "https://github.com/org/repo",
        "target_type": "invalid_type"
    })
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_scan_validation_bad_sensitivity(client: AsyncClient):
    resp = await client.post("/api/scan", json={
        "target": "https://github.com/org/repo",
        "data_sensitivity": "ultra_top_secret"
    })
    assert resp.status_code == 422


@pytest.mark.anyio
async def test_list_scans(client: AsyncClient):
    resp = await client.get("/api/scans")
    assert resp.status_code == 200
    data = resp.json()
    assert "scans" in data
    assert "total" in data
    assert "page" in data


@pytest.mark.anyio
async def test_list_scans_pagination(client: AsyncClient):
    resp = await client.get("/api/scans?page=1&page_size=5")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["scans"]) <= 5


# ── Knowledge base ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_retrieve_knowledge(client: AsyncClient):
    resp = await client.post("/api/knowledge/retrieve", json={
        "query": "RSA quantum vulnerability migration",
        "top_k": 3
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert "query" in data


@pytest.mark.anyio
async def test_quick_retrieve(client: AsyncClient):
    resp = await client.get("/api/retrieve?query=AES+symmetric+encryption")
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data


@pytest.mark.anyio
async def test_index_document(client: AsyncClient):
    resp = await client.post("/api/knowledge/index", json={
        "algorithm": "TEST-ALGO-999",
        "content": "This is a test algorithm for unit testing purposes only.",
        "source": "test-suite"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["indexed"] is True
    assert "doc_id" in data


@pytest.mark.anyio
async def test_list_algorithms(client: AsyncClient):
    resp = await client.get("/api/knowledge/algorithms")
    assert resp.status_code == 200
    data = resp.json()
    assert "algorithms" in data
    assert isinstance(data["total"], int)


# ── Risk endpoints ─────────────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_hndl_calculator(client: AsyncClient):
    resp = await client.post("/api/risk/score", json={
        "algorithm": "RSA-2048",
        "data_sensitivity": "medical",
        "exposure_years": 10
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "hndl_score" in data
    assert 0 <= data["hndl_score"] <= 10
    assert data["risk_band"] in ("critical", "high", "medium", "low", "minimal")


@pytest.mark.anyio
async def test_project_risk_404_unknown(client: AsyncClient):
    resp = await client.get("/api/risk/project/definitely-nonexistent-project-xyz")
    assert resp.status_code == 404


# ── Auth / rate limiting ───────────────────────────────────────────────────────
@pytest.mark.anyio
async def test_missing_api_key_401():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        resp = await c.get("/api/scans")
        assert resp.status_code == 401


@pytest.mark.anyio
async def test_invalid_api_key_403():
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
        headers={"X-API-Key": "totally-wrong-key"},
    ) as c:
        resp = await c.get("/api/scans")
        assert resp.status_code == 403


@pytest.mark.anyio
async def test_health_no_auth_required():
    """Health endpoint should work without an API key."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        resp = await c.get("/api/health")
        assert resp.status_code == 200
