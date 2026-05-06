"""
routers/knowledge.py — Crypto knowledge base management.

Endpoints:
  POST /api/knowledge/index      — Index a document into BM25 + Pinecone
  POST /api/knowledge/retrieve   — Hybrid retrieval query
  POST /api/knowledge/seed       — Seed the KB with built-in NIST algorithm docs
  GET  /api/knowledge/algorithms — List all indexed algorithms
"""
from __future__ import annotations

import uuid
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models.db import get_db, CryptoKnowledgeChunk
from services.hybrid_retrieval import hybrid_retrieve, index_document, init_retrieval

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])


class IndexRequest(BaseModel):
    algorithm: str
    content: str
    source: str


class RetrievalRequest(BaseModel):
    query: str
    top_k: int = 5


# ── Built-in NIST algorithm seed data ─────────────────────────────────────────
SEED_DOCS = [
    {
        "algorithm": "RSA-2048",
        "source": "NIST SP 800-56B Rev 2",
        "content": """RSA-2048 is a public-key cryptosystem based on the integer factorisation problem.
It is considered classically secure with 2048-bit keys but is quantum-vulnerable:
Shor's algorithm can factor RSA keys in polynomial time on a sufficiently powerful quantum computer (CRQC).
NIST recommends migrating to ML-KEM (FIPS 203) for key encapsulation by 2030 per CNSA 2.0.
RSA-2048 should be considered deprecated for long-lived secrets immediately.
HNDL risk: critical for data with lifetime > 7 years."""
    },
    {
        "algorithm": "ECDSA-256",
        "source": "NIST FIPS 186-5",
        "content": """ECDSA (Elliptic Curve Digital Signature Algorithm) with P-256 curve provides 128-bit classical security.
Shor's algorithm breaks ECDSA by solving the elliptic curve discrete logarithm problem.
Migration path: ML-DSA-65 (FIPS 204, lattice-based) or SLH-DSA (FIPS 205, hash-based).
ML-DSA-65 signatures are ~3.3KB vs ECDSA's ~72 bytes — plan for bandwidth overhead.
CNSA 2.0 deadline: disallowed in classified systems by 2030."""
    },
    {
        "algorithm": "ML-KEM-768",
        "source": "NIST FIPS 203",
        "content": """ML-KEM (Module-Lattice Key Encapsulation Mechanism) is the NIST-standardised post-quantum KEM.
FIPS 203 standardised in August 2024. Replaces RSA and ECDH for key encapsulation.
ML-KEM-768 provides ~Level 3 security (192-bit classical equivalent).
Ciphertext size: 1088 bytes. Public key: 1184 bytes. Much larger than RSA-2048 (256 bytes ciphertext).
Performance: key generation ~0.25ms, encapsulation ~0.3ms on modern hardware.
Already supported in OpenSSL 3.5, BoringSSL (Chrome), and NSS (Firefox)."""
    },
    {
        "algorithm": "ML-DSA-65",
        "source": "NIST FIPS 204",
        "content": """ML-DSA (Module-Lattice Digital Signature Algorithm) standardised in FIPS 204 (August 2024).
Replaces ECDSA and RSA-PSS for digital signatures. Based on CRYSTALS-Dilithium.
ML-DSA-65: signature size 3309 bytes, public key 1952 bytes, private key 4032 bytes.
Signing: ~0.5ms, verification: ~0.2ms on modern x86. Much slower keygen than ECDSA.
Suitable for TLS mutual auth, code signing, certificate authorities."""
    },
    {
        "algorithm": "SLH-DSA",
        "source": "NIST FIPS 205",
        "content": """SLH-DSA (Stateless Hash-Based Digital Signature) standardised in FIPS 205 (August 2024).
Based on SPHINCS+. Stateless — no key state to manage, unlike XMSS.
SLH-DSA-128s: signature 7856 bytes, public key 32 bytes. Very large signatures.
Best for: firmware signing, PKI root CAs, long-term archival signatures.
Avoid for high-throughput TLS — use ML-DSA instead."""
    },
    {
        "algorithm": "AES-128",
        "source": "NIST FIPS 197",
        "content": """AES-128 is a symmetric block cipher. Grover's algorithm halves effective key length:
128-bit AES provides only 64-bit quantum security — insufficient for long-term data protection.
Immediate migration target: AES-256 (provides 128-bit quantum security, Grover-resistant).
Migration effort: low — most libraries support AES-256 as a drop-in parameter change.
CNSA 2.0: AES-256 required for classified data as of 2025."""
    },
    {
        "algorithm": "SHA-1",
        "source": "NIST SP 800-131A Rev 2",
        "content": """SHA-1 is classically broken (SHAttered collision attack, 2017) AND quantum-vulnerable.
Grover's algorithm further reduces collision resistance. Deprecated by NIST since 2011.
Migration: SHA-256 (minimum) or SHA-3-256 for new systems. SHA-1 should be removed immediately.
Risk: not just quantum — active classical exploits exist for certificate forgery."""
    },
    {
        "algorithm": "MD5",
        "source": "RFC 6151",
        "content": """MD5 is completely broken — collision attacks require seconds on commodity hardware.
Should not be used for any security purpose. Quantum vulnerability is secondary to classical breaks.
Migration: SHA-256 for integrity, Argon2id for password hashing.
Presence of MD5 in code is often shadow crypto — informal implementation outside security boundaries."""
    },
    {
        "algorithm": "DH-2048",
        "source": "NIST SP 800-56A Rev 3",
        "content": """Diffie-Hellman key exchange with 2048-bit modulus provides ~112-bit classical security.
Vulnerable to Shor's algorithm. Also vulnerable to logjam attack if parameters are shared/weak.
Migration: ML-KEM-768 for key encapsulation in TLS 1.3 and higher.
CNSA 2.0 deadline: remove from classified systems by 2028 (earlier than RSA/ECDH)."""
    },
    {
        "algorithm": "3DES",
        "source": "NIST SP 800-67 Rev 2",
        "content": """Triple DES (3DES/TDEA) is officially deprecated by NIST as of 2023.
Effective key length: 112 bits classical, ~56 bits quantum (Grover).
Sweet32 attack (birthday bound) makes 3DES dangerous in TLS after 2^32 blocks.
Migration: AES-256-GCM. All uses of 3DES should be treated as urgent."""
    },
]


@router.post("/seed")
async def seed_knowledge(db: AsyncSession = Depends(get_db)):
    """
    Seed the knowledge base with built-in NIST algorithm documentation.
    Inserts into PostgreSQL (for BM25) and upserts into Pinecone (for dense search).
    Call once after first deployment.
    """
    inserted = 0
    for doc in SEED_DOCS:
        # Check if already indexed
        existing = await db.execute(
            select(CryptoKnowledgeChunk).where(
                CryptoKnowledgeChunk.algorithm == doc["algorithm"],
                CryptoKnowledgeChunk.source == doc["source"]
            )
        )
        if existing.scalar_one_or_none():
            continue

        doc_id = str(uuid.uuid4())
        chunk = CryptoKnowledgeChunk(
            id=doc_id,
            algorithm=doc["algorithm"],
            content=doc["content"],
            source=doc["source"],
            embedding_id=doc_id,
        )
        db.add(chunk)
        await db.flush()

        # Index into Pinecone
        await index_document(doc["algorithm"], doc["content"], doc["source"], doc_id)
        inserted += 1

    await db.commit()

    # Rebuild BM25 corpus from updated Postgres data
    await init_retrieval()

    return {"message": f"Seeded {inserted} documents, skipped {len(SEED_DOCS) - inserted} existing"}


@router.post("/index")
async def index_document_endpoint(req: IndexRequest, db: AsyncSession = Depends(get_db)):
    """Add a custom document to the hybrid knowledge base."""
    doc_id = str(uuid.uuid4())
    chunk = CryptoKnowledgeChunk(
        id=doc_id,
        algorithm=req.algorithm,
        content=req.content,
        source=req.source,
        embedding_id=doc_id,
    )
    db.add(chunk)
    await db.commit()
    await index_document(req.algorithm, req.content, req.source, doc_id)
    await init_retrieval()
    return {"doc_id": doc_id, "indexed": True}


@router.post("/retrieve")
async def retrieve(req: RetrievalRequest):
    """Run hybrid BM25 + dense retrieval and return ranked results with method labels."""
    docs = await hybrid_retrieve(req.query, top_k=req.top_k)
    return {
        "query": req.query,
        "results": [
            {
                "algorithm": d.algorithm,
                "content": d.content,
                "source": d.source,
                "score": round(d.score, 4),
                "retrieval_method": d.retrieval_method,
            }
            for d in docs
        ],
    }


@router.get("/algorithms")
async def list_algorithms(db: AsyncSession = Depends(get_db)):
    """List all algorithms currently in the knowledge base."""
    result = await db.execute(select(CryptoKnowledgeChunk.algorithm, CryptoKnowledgeChunk.source))
    rows = result.all()
    return {
        "algorithms": [{"algorithm": r[0], "source": r[1]} for r in rows],
        "total": len(rows),
    }
