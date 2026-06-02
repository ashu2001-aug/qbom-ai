"""
models/db.py — SQLAlchemy async models + session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Float, Integer, JSON, Text, DateTime, func, Boolean
from uuid import uuid4
from datetime import datetime
from config import get_settings

settings = get_settings()

_is_sqlite = settings.database_url.startswith("sqlite")
engine = create_async_engine(
    settings.database_url,
    echo=False,
    **({} if _is_sqlite else {"pool_pre_ping": True}),
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    target: Mapped[str] = mapped_column(String)          # repo URL or website URL
    target_type: Mapped[str] = mapped_column(String)     # "repo" | "website"
    status: Mapped[str] = mapped_column(String, default="queued")
    findings: Mapped[list | dict | None] = mapped_column(JSON, nullable=True)
    cyclonedx_bom: Mapped[dict] = mapped_column(JSON, nullable=True)
    hndl_score: Mapped[float] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str] = mapped_column(String, nullable=True)
    data_sensitivity: Mapped[str] = mapped_column(String, server_default="medium", nullable=True)
    agent_trace: Mapped[dict] = mapped_column(JSON, nullable=True)   # LangGraph state
    eval_scores: Mapped[dict] = mapped_column(JSON, nullable=True)   # DeepEval/RAGAS
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())


class CryptoKnowledgeChunk(Base):
    """Stores crypto algorithm documentation for hybrid retrieval."""
    __tablename__ = "crypto_knowledge"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    algorithm: Mapped[str] = mapped_column(String, index=True)
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String)
    embedding_id: Mapped[str] = mapped_column(String, nullable=True)  # Pinecone vector ID


class AuditLog(Base):
    """Audit log for API key usage tracking."""
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    api_key_hash: Mapped[str] = mapped_column(String)
    tier: Mapped[str] = mapped_column(String, nullable=True)
    method: Mapped[str] = mapped_column(String)
    path: Mapped[str] = mapped_column(String)
    status_code: Mapped[int] = mapped_column(Integer)
    duration_ms: Mapped[float] = mapped_column(Float)
    ip_address: Mapped[str] = mapped_column(String, nullable=True)
    scan_id: Mapped[str] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())


class ScanFinding(Base):
    """Individual cryptographic findings for detailed querying/reporting."""
    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    scan_id: Mapped[str] = mapped_column(String, index=True)
    algorithm: Mapped[str] = mapped_column(String)
    location: Mapped[str] = mapped_column(String)
    hndl_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_shadow_crypto: Mapped[bool] = mapped_column(Boolean, default=False)
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
