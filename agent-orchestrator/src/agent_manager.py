import os
from typing import Any, Dict

from langchain_mvc_agent import create_mvc_langchain_agent
from src.config import settings


class AgentManager:
    """Manager for handling various LangChain agents"""

    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.mvc_api_url = (
            settings.MVC_API_URL if hasattr(settings, "MVC_API_URL") else "http://localhost:8000"
        )

    def initialize_mvc_agent(self):
        """Initialize the MVC API agent"""
        # Get OpenAI API key from environment or settings
        openai_api_key = os.getenv("OPENAI_API_KEY") or getattr(settings, "OPENAI_API_KEY", None)

        if not openai_api_key:
            raise ValueError("OpenAI API key is not set. Please set OPENAI_API_KEY environment variable.")

        # Create the MVC agent
        self.agents["mvc_agent"] = create_mvc_langchain_agent(
            mvc_api_url=self.mvc_api_url, openai_api_key=openai_api_key
        )

        print(f"MVC agent initialized with API URL: {self.mvc_api_url}")
        return self.agents["mvc_agent"]

    def run_agent(self, agent_name: str, query: str) -> str:
        """Run a query through the specified agent"""
        if agent_name not in self.agents:
            raise ValueError(f"Agent '{agent_name}' not found. Available agents: {list(self.agents.keys())}")

        agent = self.agents[agent_name]
        result = agent.run(query)
        return result
