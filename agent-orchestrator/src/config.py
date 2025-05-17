"""
Configuration settings for the agent orchestrator
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings"""

    MVC_API_URL: str = "http://localhost:8000"  # Default MVC API URL

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
