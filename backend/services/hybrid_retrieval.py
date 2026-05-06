"""
services/hybrid_retrieval.py — Combines BM25 keyword search with Dense
semantic search (Pinecone) using Reciprocal Rank Fusion (RRF) for more
robust retrieval of crypto algorithm knowledge.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass
from typing import Optional

from rank_bm25 import BM25Okapi
from sentence_transformers import SentenceTransformer
from pinecone import Pinecone, ServerlessSpec
from sqlalchemy import text

from config import get_settings
from models.db import AsyncSessionLocal

settings = get_settings()


@dataclass
class RetrievedDoc:
    id: str
    algorithm: str
    content: str
    source: str
    score: float
    retrieval_method: str   # "bm25" | "dense" | "hybrid"


# ── Singleton embedder (loaded once) ──────────────────────────────────────────
_embedder: Optional[SentenceTransformer] = None

def get_embedder() -> SentenceTransformer:
    global _embedder
    if _embedder is None:
        _embedder = SentenceTransformer("all-MiniLM-L6-v2")
    return _embedder


# ── Pinecone client ────────────────────────────────────────────────────────────
def get_pinecone_index():
    pc = Pinecone(api_key=settings.pinecone_api_key)
    if settings.pinecone_index not in [i.name for i in pc.list_indexes()]:
        pc.create_index(
            name=settings.pinecone_index,
            dimension=384,   # all-MiniLM-L6-v2 output dim
            metric="cosine",
            spec=ServerlessSpec(cloud="aws", region=settings.pinecone_env)
        )
    return pc.Index(settings.pinecone_index)


# ── BM25 corpus (built from Postgres at startup) ──────────────────────────────
class BM25Corpus:
    def __init__(self):
        self.docs: list[dict] = []
        self.bm25: Optional[BM25Okapi] = None

    async def build(self):
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                text("SELECT id, algorithm, content, source FROM crypto_knowledge")
            )
            self.docs = [dict(r._mapping) for r in result]

        tokenized = [doc["content"].lower().split() for doc in self.docs]
        self.bm25 = BM25Okapi(tokenized)

    def search(self, query: str, top_k: int = 10) -> list[RetrievedDoc]:
        if not self.bm25 or not self.docs:
            return []
        scores = self.bm25.get_scores(query.lower().split())
        ranked = sorted(enumerate(scores), key=lambda x: x[1], reverse=True)[:top_k]
        return [
            RetrievedDoc(
                id=self.docs[i]["id"],
                algorithm=self.docs[i]["algorithm"],
                content=self.docs[i]["content"],
                source=self.docs[i]["source"],
                score=float(s),
                retrieval_method="bm25"
            )
            for i, s in ranked if s > 0
        ]


_bm25_corpus = BM25Corpus()


async def init_retrieval():
    """Call once at app startup to load BM25 corpus."""
    await _bm25_corpus.build()


# ── Dense retrieval via Pinecone ───────────────────────────────────────────────
def dense_search(query: str, top_k: int = 10) -> list[RetrievedDoc]:
    embedder = get_embedder()
    query_vec = embedder.encode(query).tolist()

    index = get_pinecone_index()
    results = index.query(vector=query_vec, top_k=top_k, include_metadata=True)

    return [
        RetrievedDoc(
            id=m["id"],
            algorithm=m["metadata"].get("algorithm", ""),
            content=m["metadata"].get("content", ""),
            source=m["metadata"].get("source", ""),
            score=float(m["score"]),
            retrieval_method="dense"
        )
        for m in results["matches"]
    ]


# ── Reciprocal Rank Fusion ─────────────────────────────────────────────────────
def reciprocal_rank_fusion(
    bm25_results: list[RetrievedDoc],
    dense_results: list[RetrievedDoc],
    k: int = 60,
    top_k: int = 5
) -> list[RetrievedDoc]:
    """
    RRF score = Σ 1/(k + rank_i) across retrieval methods.
    Merges BM25 and dense rankings into a single ranked list.
    """
    scores: dict[str, float] = {}
    doc_map: dict[str, RetrievedDoc] = {}

    for rank, doc in enumerate(bm25_results):
        scores[doc.id] = scores.get(doc.id, 0) + 1 / (k + rank + 1)
        doc_map[doc.id] = doc

    for rank, doc in enumerate(dense_results):
        scores[doc.id] = scores.get(doc.id, 0) + 1 / (k + rank + 1)
        if doc.id not in doc_map:
            doc_map[doc.id] = doc

    ranked_ids = sorted(scores, key=lambda x: scores[x], reverse=True)[:top_k]
    results = []
    for doc_id in ranked_ids:
        doc = doc_map[doc_id]
        doc.score = scores[doc_id]
        doc.retrieval_method = "hybrid"
        results.append(doc)
    return results


# ── Public API ─────────────────────────────────────────────────────────────────
async def hybrid_retrieve(query: str, top_k: int = 5) -> list[RetrievedDoc]:
    """
    Run BM25 + Dense search in parallel, fuse with RRF.
    This is called by LangGraph agents when they need knowledge about
    a specific cryptographic algorithm.
    """
    bm25_task = asyncio.to_thread(_bm25_corpus.search, query, top_k * 2)
    dense_task = asyncio.to_thread(dense_search, query, top_k * 2)

    bm25_results, dense_results = await asyncio.gather(bm25_task, dense_task)
    fused = reciprocal_rank_fusion(bm25_results, dense_results, top_k=top_k)

    # Record OTel metrics for retrieval quality tracking
    try:
        from observability.telemetry import record_retrieval_metrics
        record_retrieval_metrics(
            query=query,
            bm25_count=len(bm25_results),
            dense_count=len(dense_results),
            rrf_count=len(fused),
        )
    except Exception:
        pass

    return fused


async def index_document(algorithm: str, content: str, source: str, doc_id: str):
    """Upsert a document into Pinecone for dense retrieval."""
    embedder = get_embedder()
    vector = embedder.encode(content).tolist()
    index = get_pinecone_index()
    index.upsert(vectors=[{
        "id": doc_id,
        "values": vector,
        "metadata": {"algorithm": algorithm, "content": content[:1000], "source": source}
    }])
