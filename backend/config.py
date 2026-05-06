"""
config.py — centralised settings loaded from environment variables.
"""
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_api_key: str = ""
    azure_openai_deployment: str = "gpt-4o"
    azure_openai_api_version: str = "2024-08-01-preview"

    # LangSmith
    langchain_tracing_v2: bool = True
    langchain_api_key: str = ""
    langchain_project: str = "qbom-ai"

    # Pinecone
    pinecone_api_key: str = ""
    pinecone_index: str = "qbom-crypto-index"
    pinecone_env: str = "us-east-1"

    # PostgreSQL
    database_url: str = "postgresql+asyncpg://user:password@localhost:5432/qbom"
    supabase_url: str = ""
    supabase_key: str = ""

    # HuggingFace
    hf_token: str = ""

    # App
    secret_key: str = "change-me"
    environment: str = "development"

    # OpenTelemetry
    otel_exporter_otlp_endpoint: str = ""
    applicationinsights_connection_string: str = ""

    class Config:
        env_file = ".env"
        case_sensitive = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
