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

        # Extract information from the ElasticAlertData model
        processed_alert = {
            "timestamp": alert_data.get("timestamp"),
            "request_id": alert_data.get("id"),
            "method": alert_data.get("method"),
            "url": alert_data.get("url"),
            "remote_addr": alert_data.get("remote_addr"),
            "user_agent": alert_data.get("user_agent"),
        }

        # Extract parsed alert information if available
        if alert_data.get("alert"):
            alert_info = alert_data["alert"]
            processed_alert.update(
                {
                    "alert_id": alert_info.get("id"),
                    "alert_uuid": alert_info.get("uuid"),
                    "action_group": alert_info.get("action_group"),
                    "action_group_name": alert_info.get("action_group_name"),
                    "flapping": alert_info.get("flapping"),
                    "consecutive_matches": alert_info.get("consecutive_matches"),
                }
            )

        # Extract parsed rule information if available
        if alert_data.get("rule"):
            rule_info = alert_data["rule"]
            rule_params = rule_info.get("params", {})
            processed_alert.update(
                {
                    "rule_id": rule_info.get("id"),
                    "rule_name": rule_info.get("name"),
                    "rule_type": rule_info.get("type"),
                    "rule_url": rule_info.get("url"),
                    "rule_tags": rule_info.get("tags", []),
                    "space_id": rule_info.get("space_id"),
                    "rule_description": rule_params.get("description"),
                    "severity": rule_params.get("severity", "medium"),
                    "risk_score": rule_params.get("risk_score"),
                    "threat": rule_params.get("threat", []),
                    "query": rule_params.get("query"),
                    "false_positives": rule_params.get("false_positives", []),
                    "references": rule_params.get("references", []),
                    "mitre_tactics": [],
                    "mitre_techniques": [],
                }
            )

            # Extract MITRE ATT&CK information from threat field
            for threat_item in rule_params.get("threat", []):
                if threat_item.get("tactic"):
                    processed_alert["mitre_tactics"].append(
                        {
                            "id": threat_item["tactic"].get("id"),
                            "name": threat_item["tactic"].get("name"),
                            "reference": threat_item["tactic"].get("reference"),
                        }
                    )

                for technique in threat_item.get("technique", []):
                    technique_info = {
                        "id": technique.get("id"),
                        "name": technique.get("name"),
                        "reference": technique.get("reference"),
                        "subtechniques": [],
                    }

                    for subtechnique in technique.get("subtechnique", []):
                        technique_info["subtechniques"].append(
                            {
                                "id": subtechnique.get("id"),
                                "name": subtechnique.get("name"),
                                "reference": subtechnique.get("reference"),
                            }
                        )

                    processed_alert["mitre_techniques"].append(technique_info)

        # Extract context data (contains actual alert events with IoCs!)
        if alert_data.get("context"):
            context_info = alert_data["context"]
            processed_alert["context"] = context_info
            # If there are alerts in the context, that's where the real IoCs are
            if isinstance(context_info, dict) and context_info.get("alerts"):
                processed_alert["alert_events"] = context_info["alerts"]

        # Extract state data (additional alert metadata)
        if alert_data.get("state"):
            processed_alert["state"] = alert_data["state"]

        return {"processed_alert": processed_alert}
