from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors.pipeline_processor import PipelineStep


class MCPQueryStep(PipelineStep):
    """Execute a query through the integrated MCP client"""

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client

    @property
    def required_inputs(self) -> list[str]:
        return ["prompt"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["mcp_response"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process a query through the integrated MCP client"""
        if not self.mcp_client:
            raise ValueError("Integrated MCP client not initialized")

        prompt = data["prompt"]
        logger.info("Processing Prompt", {"prompt": prompt})

        # Get optional configuration parameters
        model = data.get("model", "claude-3-5-sonnet-20241022")
        max_tokens = data.get("max_tokens", 1000)
        temperature = data.get("temperature", 0.5)

        # Process the query using integrated MCP client with custom parameters
        response = await self.mcp_client.process_query(
            prompt, model=model, max_tokens=max_tokens, temperature=temperature
        )

        logger.info("MCP Response", {"response": response})

        return {"mcp_response": response}
