import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration class for the agent orchestrator (Singleton)"""

    _instance = None
    _initialized = False
    api_key: str
    abuseipdb_api_key: str

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
            # For testing purposes, allow empty API key
            try:
                self.api_key = self.get_env("ANTHROPIC_API_KEY")
            except ValueError:
                # Use a placeholder for testing - in production this should be set
                self.api_key = "test-api-key-placeholder"
                print("Warning: Using placeholder API key for testing. Set ANTHROPIC_API_KEY environment variable for production.")
            
            # Load AbuseIPDB API key
            try:
                self.abuseipdb_api_key = self.get_env("ABUSEIPDB_API_KEY")
            except ValueError:
                # Use a placeholder for testing
                self.abuseipdb_api_key = "test-abuseipdb-key-placeholder"
                print("Warning: Using placeholder AbuseIPDB API key for testing. Set ABUSEIPDB_API_KEY environment variable for production.")
            
            Config._initialized = True
