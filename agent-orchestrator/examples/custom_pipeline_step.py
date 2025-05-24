from typing import Any, Dict, List

from src.pipeline_processor import PipelineStep


class CustomAlertEnrichmentStep(PipelineStep):
    """Example of a custom pipeline step to enrich alert data"""

    @property
    def required_inputs(self) -> List[str]:
        return ["processed_alert"]

    @property
    def provided_outputs(self) -> List[str]:
        return ["enriched_alert"]

    async def process(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the alert data with additional information"""
        processed_alert = data["processed_alert"]

        # This is where you would add your own logic to enrich the alert
        # For example, you might:
        # - Lookup IP addresses in a threat intelligence database
        # - Add user information from a user directory
        # - Check if similar alerts have been seen recently

        enriched_alert = processed_alert.copy()

        # Example enrichment: classify the alert based on type and severity
        if processed_alert["alert_type"] == "security_alert" and processed_alert["severity"] == "high":
            enriched_alert["risk_score"] = 90
            enriched_alert["recommended_action"] = "immediate_investigation"
        elif processed_alert["severity"] == "medium":
            enriched_alert["risk_score"] = 60
            enriched_alert["recommended_action"] = "scheduled_review"
        else:
            enriched_alert["risk_score"] = 30
            enriched_alert["recommended_action"] = "log_only"

        return {"enriched_alert": enriched_alert}


# Example of how to register and use this custom step:
"""
# In your application code:
from examples.custom_pipeline_step import CustomAlertEnrichmentStep

# Register the custom step
agent_manager.pipeline_processor.register_step("alert_enrichment", CustomAlertEnrichmentStep())

# Use a custom pipeline that includes this step
custom_pipeline = [
    "alert_processing",
    "alert_enrichment",  # Add the custom step in the pipeline
    "prompt_generation",
    "mcp_query",
    "response_formatting"
]

# Process with the custom pipeline
result = await agent_manager.pipeline_processor.process(
    initial_data,
    custom_pipeline
)
"""
