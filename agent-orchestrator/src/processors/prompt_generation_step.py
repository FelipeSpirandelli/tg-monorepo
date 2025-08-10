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
