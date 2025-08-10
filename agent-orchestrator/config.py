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
            cls._instance = super(Config, cls).__new__(cls)
        return cls._instance

    def get_env(self, key: str) -> str:
        if key not in os.environ:
            raise ValueError(f"Environment variable {key} is not set")
        return os.getenv(key)

    def __init__(self):
        if not Config._initialized:
            self.api_key = self.get_env("API_KEY")
            Config._initialized = True
