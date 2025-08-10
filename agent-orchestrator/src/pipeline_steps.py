from typing import Any

from src.mcp_client import IntegratedMCPClient
from src.pipeline_processor import PipelineStep


class AlertProcessingStep(PipelineStep):
    """Process incoming alert data"""

    @property
    def required_inputs(self) -> list[str]:
        return ["alert_data"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["processed_alert"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process the alert data"""
        alert_data = data["alert_data"]

        processed_alert = {
            "alert_type": alert_data.get("type", "unknown"),
            "source": alert_data.get("source", "unknown"),
            "severity": alert_data.get("severity", "medium"),
            "timestamp": alert_data.get("timestamp"),
            "details": alert_data.get("details", {}),
        }

        return {"processed_alert": processed_alert}


class PromptGenerationStep(PipelineStep):
    """Generate a prompt for the AI based on processed alert data"""

    @property
    def required_inputs(self) -> list[str]:
        return ["processed_alert"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["prompt", "prompt_context"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate a prompt for the AI"""
        processed_alert = data["processed_alert"]
        prompt_template = data.get("prompt_template", self._get_default_prompt_template())

        # Build context for the prompt
        prompt_context = {
            "alert": processed_alert,
            "tools_instruction": "You can use available tools to help analyze and respond to this alert.",
        }

        # Format the prompt with the template and context
        prompt = prompt_template.format(**prompt_context)

        return {"prompt": prompt, "prompt_context": prompt_context}

    def _get_default_prompt_template(self) -> str:
        """Get the default prompt template"""
        return """
I received an alert with the following information:
- Type: {alert[alert_type]}
- Source: {alert[source]}
- Severity: {alert[severity]}
- Timestamp: {alert[timestamp]}

Details:
{alert[details]}

{tools_instruction}

Please analyze this alert and recommend appropriate actions.
"""


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

        # Get optional configuration parameters
        model = data.get("model", "claude-3-5-sonnet-20241022")
        max_tokens = data.get("max_tokens", 1000)
        temperature = data.get("temperature", 0.5)

        # Process the query using integrated MCP client with custom parameters
        response = await self.mcp_client.process_query(
            prompt, model=model, max_tokens=max_tokens, temperature=temperature
        )

        return {"mcp_response": response}


class ResponseFormattingStep(PipelineStep):
    """Format the response for the user"""

    @property
    def required_inputs(self) -> list[str]:
        return ["mcp_response", "processed_alert"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["formatted_response"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Format the response"""
        mcp_response = data["mcp_response"]
        processed_alert = data["processed_alert"]

        # Create a formatted response
        formatted_response = {
            "alert_summary": {
                "type": processed_alert["alert_type"],
                "source": processed_alert["source"],
                "severity": processed_alert["severity"],
            },
            "ai_response": mcp_response,
            "timestamp": processed_alert.get("timestamp"),
        }

        return {"formatted_response": formatted_response}
