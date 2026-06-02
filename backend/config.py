"""
config.py — centralised settings loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # LLM Provider — "gemini" (default for local) or "azure"
    llm_provider: str = "gemini"

    # Google Gemini
    google_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    # Azure OpenAI (used when llm_provider="azure")
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-08-01-preview"

    # LangSmith
    langchain_tracing_v2: bool = False
    langchain_api_key: str = ""
    langchain_project: str = "qbom-ai"

    # Pinecone (optional — leave blank to use BM25-only retrieval)
    pinecone_api_key: str = ""
    pinecone_index: str = "qbom-crypto-index"
    pinecone_env: str = "us-east-1"

    # Database — defaults to local SQLite for easy testing
    database_url: str = "sqlite+aiosqlite:///./qbom_local.db"
    supabase_url: str = ""
    supabase_key: str = ""

    # HuggingFace
    hf_token: str = ""

    # App
    secret_key: str = "change-me"
    environment: str = "development"
    scheduler_enabled: bool = False

    # OpenTelemetry
    otel_exporter_otlp_endpoint: str = ""
    applicationinsights_connection_string: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
