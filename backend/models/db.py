"""
models/db.py — SQLAlchemy async models + session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import String, Float, JSON, Text, DateTime, func
from uuid import uuid4
from datetime import datetime
from config import get_settings

settings = get_settings()

engine = create_async_engine(settings.database_url, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid4()))
    target: Mapped[str] = mapped_column(String)          # repo URL or website URL
    target_type: Mapped[str] = mapped_column(String)     # "repo" | "website"
    status: Mapped[str] = mapped_column(String, default="queued")
    findings: Mapped[dict] = mapped_column(JSON, nullable=True)
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


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
