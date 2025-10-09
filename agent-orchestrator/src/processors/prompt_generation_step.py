from typing import Any

from src.processors.pipeline_processor import PipelineStep


class PromptGenerationStep(PipelineStep):
    """Generate a prompt for the AI based on processed alert data"""

    @property
    def required_inputs(self) -> list[str]:
        return ["natural_language_summary", "analyst_ready_report"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["prompt", "prompt_context"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Generate a prompt for the AI based on Rule-to-Text pipeline output"""
        natural_language_summary = data["natural_language_summary"]
        analyst_ready_report = data["analyst_ready_report"]
        
        # Check if we have legacy processed_alert for backward compatibility
        if "processed_alert" in data and not natural_language_summary:
            return await self._process_legacy_format(data)
        
        # Use the new Rule-to-Text format
        prompt_template = data.get("prompt_template", self._get_rule_to_text_prompt_template())

        # Extract actual IoCs from the data
        extracted_iocs = data.get("extracted_iocs", {})
        actual_iocs_text = self._format_iocs_for_prompt(extracted_iocs)
        
        # Build context for the prompt
        prompt_context = {
            "summary": natural_language_summary,
            "report": analyst_ready_report,
            "actual_iocs": actual_iocs_text,
            "tools_instruction": "You can use available tools to provide additional analysis and recommendations.",
        }

        # Format the prompt with the template and context
        prompt = prompt_template.format(**prompt_context)

        return {"prompt": prompt, "prompt_context": prompt_context}

    def _format_iocs_for_prompt(self, extracted_iocs: dict[str, list]) -> str:
        """Format extracted IoCs in a clear way for the LLM"""
        ioc_lines = []
        
        # IP Addresses - Most important for threat intel
        if extracted_iocs.get("ip_addresses"):
            ioc_lines.append("**IP Addresses to investigate:**")
            for ip in extracted_iocs["ip_addresses"]:
                ioc_lines.append(f"  - {ip}")
            ioc_lines.append("")
        
        # Domains
        if extracted_iocs.get("domains"):
            ioc_lines.append("**Domains:**")
            for domain in extracted_iocs["domains"]:
                ioc_lines.append(f"  - {domain}")
            ioc_lines.append("")
        
        # File Hashes
        if extracted_iocs.get("file_hashes"):
            ioc_lines.append("**File Hashes:**")
            for hash_val in extracted_iocs["file_hashes"]:
                ioc_lines.append(f"  - {hash_val}")
            ioc_lines.append("")
        
        # URLs (limit to avoid clutter)
        if extracted_iocs.get("urls"):
            ioc_lines.append("**URLs (first 3):**")
            for url in extracted_iocs["urls"][:3]:
                ioc_lines.append(f"  - {url}")
            ioc_lines.append("")
        
        # MITRE Techniques
        if extracted_iocs.get("mitre_techniques"):
            ioc_lines.append("**MITRE ATT&CK Techniques:**")
            for technique in extracted_iocs["mitre_techniques"]:
                ioc_lines.append(f"  - {technique}")
            ioc_lines.append("")
        
        # Ports
        if extracted_iocs.get("ports"):
            ioc_lines.append("**Ports:**")
            for port in extracted_iocs["ports"]:
                ioc_lines.append(f"  - {port}")
            ioc_lines.append("")
        
        if not ioc_lines:
            return "No specific IoCs extracted from this alert."
        
        return "\n".join(ioc_lines)

    async def _process_legacy_format(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process legacy format for backward compatibility"""
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

    def _get_rule_to_text_prompt_template(self) -> str:
        """Get the Rule-to-Text prompt template for the new format"""
        return """
I received a security alert that has been processed and analyzed. Here's the information:

## Alert Summary:
{summary}

## Detailed Analysis:
{report}

## Extracted Indicators of Compromise (IoCs):
{actual_iocs}

{tools_instruction}

Please analyze this security alert and provide:
1. A comprehensive threat assessment
2. Potential impact analysis
3. Recommended immediate response actions
4. Detailed investigation steps
5. Long-term prevention and mitigation strategies

Use the extracted IoCs to provide specific, actionable intelligence. Focus on the technical details
and provide concrete recommendations that can be implemented by security teams.

If you need additional threat intelligence or context, use the available tools to gather more information
about the IoCs, MITRE techniques, or related threats.
"""

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
