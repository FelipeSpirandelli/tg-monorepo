import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration class for the agent orchestrator (Singleton)"""

    _instance = None
    _initialized = False
    api_key: str

    # RAG System Configuration
    qdrant_url: str
    qdrant_api_key: str | None
    qdrant_collection: str
    embedding_model: str
    abuseipdb_api_key: str

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def get_env(self, key: str, default: str | None = None) -> str:
        value = os.getenv(key, default)
        if value is None:
            raise ValueError(f"Environment variable {key} is not set")
        return value

    def get_env_optional(self, key: str, default: str | None = None) -> str | None:
        """Get environment variable with optional default, can return None"""
        return os.getenv(key, default)

    def __init__(self):
        if not Config._initialized:
            # For testing purposes, allow empty API key
            try:
                self.api_key = self.get_env("ANTHROPIC_API_KEY")

                # RAG System Configuration
                self.qdrant_url = self.get_env("QDRANT_URL", "http://localhost:6333")
                self.qdrant_api_key = self.get_env_optional("QDRANT_API_KEY")
                self.qdrant_collection = self.get_env("QDRANT_COLLECTION", "pdf_rag")
                self.embedding_model = self.get_env(
                    "EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
                )

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
