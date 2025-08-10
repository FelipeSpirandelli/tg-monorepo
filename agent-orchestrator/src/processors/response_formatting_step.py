from typing import Any

from src.processors.pipeline_processor import PipelineStep


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
