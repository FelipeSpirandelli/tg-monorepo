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
        processed_alert = data.get("processed_alert", {})

        # Handle both legacy and new pipeline formats
        alert_type = processed_alert.get("alert_type", "security_alert")
        source = processed_alert.get("source", "elastic_security")
        severity = processed_alert.get("severity", "medium")
        timestamp = processed_alert.get("timestamp")
        
        # For new pipeline, try to get info from rule data
        if "alert_data" in data:
            alert_data = data["alert_data"]
            rule_info = alert_data.get("rule") or {}
            params = rule_info.get("params") or {}
            alert_type = rule_info.get("name", alert_type)
            severity = params.get("severity", severity)
            if not timestamp:
                timestamp = alert_data.get("timestamp")

        # Create a formatted response
        formatted_response = {
            "alert_summary": {
                "type": alert_type,
                "source": source,
                "severity": severity,
            },
            "ai_response": mcp_response,
            "timestamp": timestamp,
        }

        return {"formatted_response": formatted_response}
