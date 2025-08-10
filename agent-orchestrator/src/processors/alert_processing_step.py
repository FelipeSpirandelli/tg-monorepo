from typing import Any

from src.processors.pipeline_processor import PipelineStep


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
