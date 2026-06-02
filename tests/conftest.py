"""
tests/conftest.py — Shared pytest fixtures and global mocking.
Patches all external services so no test ever makes a real API call.
"""
from __future__ import annotations
import os, json, pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Set env vars BEFORE any app module is imported
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://qbom:qbom_dev_password@localhost:5432/qbom_test")
os.environ.setdefault("AZURE_OPENAI_API_KEY", "test-key-not-real")
os.environ.setdefault("OPENAI_API_KEY", "test-key-not-real")
os.environ.setdefault("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com/")

os.environ.setdefault("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
os.environ.setdefault("AZURE_OPENAI_API_VERSION", "2024-08-01-preview")
os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGCHAIN_API_KEY", "test-key-not-real")
os.environ.setdefault("PINECONE_API_KEY", "test-key-not-real")
os.environ.setdefault("PINECONE_INDEX", "qbom-test-index")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SCHEDULER_ENABLED", "false")

# Mock LLM responses in rotation
_RESPONSES = [
    "scanner",
    "enricher",
    json.dumps([{"algorithm": "RSA-2048", "location": "auth.py:42", "hndl_score": 8.5,
                 "quantum_vulnerable": True, "is_shadow_crypto": False,
                 "migration_path": "ML-KEM-768 (FIPS 203)"}]),
    "APPROVED - quality score 0.87",
    "reporter",
]
_call_n = {"n": 0}


def _make_ai_msg(content: str):
    from langchain_core.messages import AIMessage
    msg = AIMessage(content=content)
    msg.tool_calls = []
    return msg


@pytest.fixture(scope="session", autouse=True)
def mock_azure_openai():
    """Block all Azure OpenAI calls for the entire test session."""
    async def _ainvoke(messages, **kw):
        idx = _call_n["n"] % len(_RESPONSES)
        _call_n["n"] += 1
        return _make_ai_msg(_RESPONSES[idx])

    mock_llm = MagicMock()
    mock_llm.ainvoke = AsyncMock(side_effect=_ainvoke)
    mock_llm.invoke = MagicMock(side_effect=lambda m, **kw: _make_ai_msg(_RESPONSES[0]))
    mock_llm.bind_tools = MagicMock(return_value=mock_llm)

    with patch("agents.qbom_graph.llm", mock_llm), \
         patch("agents.qbom_graph.llm_with_tools", mock_llm):
        yield mock_llm


@pytest.fixture(scope="session", autouse=True)
def mock_pinecone():
    """Block all Pinecone calls."""
    mock_idx = MagicMock()
    mock_idx.query.return_value = {"matches": [
        {"id": "d1", "score": 0.91,
         "metadata": {"algorithm": "RSA-2048",
                      "content": "RSA quantum-vulnerable. Migrate to ML-KEM-768.",
                      "source": "NIST"}}
    ]}
    mock_idx.upsert.return_value = {"upserted_count": 1}
    mock_pc = MagicMock()
    mock_pc.Index.return_value = mock_idx
    mock_pc.list_indexes.return_value = [MagicMock(name="qbom-test-index")]

    with patch("pinecone.Pinecone", return_value=mock_pc), \
         patch("services.hybrid_retrieval.get_pinecone_index", return_value=mock_idx):
        yield mock_pc


@pytest.fixture(scope="session", autouse=True)
def mock_sentence_transformer():
    """Block SentenceTransformer model download."""
    import numpy as np
    mock_model = MagicMock()
    mock_model.encode.return_value = np.random.rand(384).astype("float32")
    with patch("services.hybrid_retrieval.get_embedder", return_value=mock_model):
        yield mock_model


@pytest.fixture(scope="session", autouse=True)
def mock_langsmith():
    mock_client = MagicMock()
    mock_client.create_feedback.return_value = None
    with patch("evaluation.harness.LangSmithClient", return_value=mock_client):
        yield mock_client


@pytest.fixture(scope="session")
def mock_findings():
    return [
        {"algorithm": "RSA-2048",  "location": "auth.py:42",     "hndl_score": 8.5,  "quantum_vulnerable": True,  "is_shadow_crypto": False, "migration_path": "ML-KEM-768"},
        {"algorithm": "ECDSA-256", "location": "sign.py:17",     "hndl_score": 8.2,  "quantum_vulnerable": True,  "is_shadow_crypto": False, "migration_path": "ML-DSA-65"},
        {"algorithm": "MD5",       "location": "legacy.py:8",    "hndl_score": 6.0,  "quantum_vulnerable": True,  "is_shadow_crypto": True,  "migration_path": "SHA-256"},
        {"algorithm": "AES-256",   "location": "cipher.py:29",   "hndl_score": 1.0,  "quantum_vulnerable": False, "is_shadow_crypto": False, "migration_path": "No change"},
        {"algorithm": "SHA-256",   "location": "api/token.js:14","hndl_score": 0.5,  "quantum_vulnerable": False, "is_shadow_crypto": False, "migration_path": "No change"},
    ]

@pytest.fixture
def sample_repo_url():    return "https://github.com/psf/requests"
@pytest.fixture
def sample_website_url(): return "https://example.com"

@pytest.fixture
def mock_scan_record():
    from unittest.mock import MagicMock
    from datetime import datetime
    s = MagicMock()
    s.id = "test-scan-00000001"
    s.target = "https://github.com/test/repo"
    s.target_type = "repo"
    s.status = "complete"
    s.hndl_score = 8.5
    s.risk_level = "critical"
    s.created_at = datetime(2025, 6, 1, 12, 0, 0)
    s.agent_trace = {"reflection_iterations": 1, "reflection_passed": True, "message_count": 14}
    s.findings = [{"algorithm": "RSA-2048", "location": "auth.py:42", "hndl_score": 8.5,
                   "quantum_vulnerable": True, "is_shadow_crypto": False, "migration_path": "ML-KEM-768"}]
    return s
