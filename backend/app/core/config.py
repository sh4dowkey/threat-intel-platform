from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    # App
    environment: str = "development"
    secret_key: str

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # APIs
    virustotal_api_key: str
    abuseipdb_api_key: str
    otx_api_key: str
    groq_api_key: str
    groq_model: str = "llama3-8b-8192"

    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings() -> Settings:
    return Settings()