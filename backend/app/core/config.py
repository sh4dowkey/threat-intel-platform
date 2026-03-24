from pydantic_settings import BaseSettings
from functools import lru_cache
from pathlib import Path

# Fallback path for local development
_DEFAULT_MODELS_DIR = str(
    Path(__file__).resolve().parent.parent.parent.parent / "ml" / "models"
)


class Settings(BaseSettings):
    # App
    environment: str = "development"
    secret_key: str

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # External APIs
    virustotal_api_key: str
    abuseipdb_api_key: str
    otx_api_key: str = ""          # optional
    groq_api_key: str
    groq_model: str = "llama3-8b-8192"

    # ML models directory
    # In production (Railway): set MODELS_DIR=/app/models
    # In development: defaults to ml/models/ relative to project root
    models_dir: str = _DEFAULT_MODELS_DIR

    class Config:
        env_file = str(Path(__file__).resolve().parent.parent.parent / ".env")
        case_sensitive = False


@lru_cache()
def get_settings() -> Settings:
    return Settings()
