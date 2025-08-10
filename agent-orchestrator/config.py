import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration class for the agent orchestrator (Singleton)"""

    _instance = None
    _initialized = False
    api_key: str

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_env(self, key: str) -> str:
        value = os.getenv(key, None)
        if value is None:
            raise ValueError(f"Environment variable {key} is not set")
        return value

    def __init__(self):
        if not Config._initialized:
            self.api_key = self.get_env("API_KEY")
            Config._initialized = True
