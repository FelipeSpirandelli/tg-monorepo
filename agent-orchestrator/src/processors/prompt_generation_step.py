from typing import Any

from src.processors.pipeline_processor import PipelineStep


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

        # Validate processed_alert is a dictionary
        if not isinstance(processed_alert, dict):
            raise ValueError("processed_alert must be a dictionary")

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
I received an alert from Elastic Security with the following information:

## Alert Details:
- Alert ID: {alert[alert_id]}
- Alert UUID: {alert[alert_uuid]}
- Timestamp: {alert[timestamp]}
- Action Group: {alert[action_group_name]}
- Flapping: {alert[flapping]}
- Consecutive Matches: {alert[consecutive_matches]}

## Rule Information:
- Rule Name: {alert[rule_name]}
- Rule ID: {alert[rule_id]}
- Severity: {alert[severity]}
- Risk Score: {alert[risk_score]}
- Rule Type: {alert[rule_type]}
- Description: {alert[rule_description]}

## MITRE ATT&CK Framework:
- Tactics: {alert[mitre_tactics]}
- Techniques: {alert[mitre_techniques]}

## Query Details:
{alert[query]}

## References:
{alert[references]}

## False Positives:
{alert[false_positives]}

{tools_instruction}

Please analyze this security alert and provide:
1. A summary of the threat
2. Potential impact assessment
3. Recommended immediate actions
4. Investigation steps to take
5. Prevention measures to consider

Focus particularly on the MITRE ATT&CK techniques and tactics identified to provide
context-aware recommendations.
"""
