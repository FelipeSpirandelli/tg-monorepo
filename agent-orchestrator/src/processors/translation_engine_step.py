from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors.pipeline_processor import PipelineStep


class TranslationEngineStep(PipelineStep):
    """
    Translation Engine - Third step of Rule-to-Text pipeline

    Converts enriched technical data into clear, natural language explanations
    that are easy for analysts to understand and act upon using LLM analysis.
    """

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client

    @property
    def required_inputs(self) -> list[str]:
        return ["extracted_iocs", "enriched_alert"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["natural_language_summary", "analyst_ready_report"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Create initial natural language summary of alert and IoCs"""
        extracted_iocs = data["extracted_iocs"]
        enriched_alert = data["enriched_alert"]

        logger.info("Starting translation engine process - creating initial summary")

        # Create initial summary without MCP calls (LLM will enhance this later)
        initial_summary = await self._generate_initial_summary(enriched_alert, extracted_iocs)

        # Create basic analyst report structure
        analyst_report = self._create_initial_analyst_report(enriched_alert, extracted_iocs)

        # Fallback to template if LLM fails
        if not initial_summary:
            logger.warning("LLM summary generation failed, using simple template fallback")
            initial_summary = await self._generate_template_summary(enriched_alert, extracted_iocs)

        logger.info("Translation engine completed - initial summary ready for LLM enhancement")

        return {"natural_language_summary": initial_summary, "analyst_ready_report": analyst_report}

    async def _generate_initial_summary(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Generate initial summary using LLM with RAG-based playbook recommendations"""
        try:
            prompt = await self._create_initial_summary_prompt(alert, iocs)

            response = await self.mcp_client.process_query(
                prompt, model="claude-sonnet-4-5-20250929", max_tokens=1500, temperature=0.3
            )

            logger.info("Successfully generated initial summary with RAG playbook recommendation")
            return response

        except Exception as e:
            logger.error(f"Error generating initial summary: {str(e)}")
            return ""

    async def _create_initial_summary_prompt(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Create prompt for concise, actionable summary using RAG-retrieved playbooks"""

        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity") or "medium"  # Handle None values
        description = alert.get("rule_description", "")
        
        # Build severity line only if we have a meaningful severity
        severity_line = f"- Severity: {severity.upper()}" if severity and severity != "medium" else ""

        # Summarize IoCs
        ioc_summary = []
        total_iocs = 0
        for ioc_type, values in iocs.items():
            if values:
                count = len(values)
                total_iocs += count
                ioc_summary.append(f"- {ioc_type}: {count} found")

        mitre_techniques = alert.get("mitre_techniques", [])
        mitre_info = ""
        if mitre_techniques:
            techniques = [
                f"{t.get('id', 'Unknown')} ({t.get('name', 'Unknown')})" for t in mitre_techniques[:3]
            ]
            mitre_info = f"MITRE ATT&CK Techniques: {', '.join(techniques)}"

        prompt = f"""You are a SOC analyst providing a concise alert summary for immediate action.

SECURITY ALERT DETAILS:
- Rule: {rule_name}
{severity_line}
- Description: {description}
{mitre_info}

EXTRACTED INDICATORS OF COMPROMISE:
{chr(10).join(ioc_summary) if ioc_summary else "- No significant IoCs extracted"}
Total IoCs: {total_iocs}

Use the available RAG tools to search for the most relevant security playbook for this alert.
Query the playbook system based on the alert details above to find appropriate response procedures.

Provide a focused response with exactly these 3 sections:

**1. WHAT HAPPENED (2 lines maximum):**
Brief explanation of the security event and primary threat indicators.

**2. IMMEDIATE MITIGATION REQUIRED:**
Answer: YES or NO - Does this require immediate action to prevent damage?

**3. RECOMMENDED PLAYBOOK:**
Use the RAG system to find the most relevant playbook for this incident type. Only provide the playbook name.

Be concise and actionable. Focus on what the analyst needs to know and do right now."""

        return prompt

    def _create_initial_analyst_report(self, alert: dict[str, Any], iocs: dict[str, list]) -> dict[str, Any]:
        """Create concise analyst report structure"""

        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity") or "medium"  # Handle None values
        total_iocs = sum(len(values) for values in iocs.values())
        
        # Format severity for display (don't show if it's just the default)
        severity_display = f"({severity})" if severity and severity not in ["medium", "unknown"] else ""

        return {
            "alert_summary": f"Alert: {rule_name} {severity_display} - {total_iocs} IoCs".strip(),
            "immediate_action_required": "PENDING_ANALYSIS",  # Will be filled by LLM
            "recommended_playbook": "PENDING_ANALYSIS",  # Will be filled by LLM
            "alert_details": {
                "rule_name": rule_name,
                "severity": severity,
                "total_iocs": total_iocs,
                "mitre_techniques": [t.get("id") for t in alert.get("mitre_techniques", [])],
            },
            "iocs": iocs,
            "status": "concise_analysis_ready",
        }

    async def _generate_template_summary(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Generate concise template-based fallback summary"""

        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity") or "medium"  # Handle None values
        total_iocs = sum(len(values) for values in iocs.values())
        
        # Get rule description for more context
        description = alert.get("rule_description", "")

        summary = "**1. WHAT HAPPENED:**\n"
        summary += f"{rule_name} triggered with {total_iocs} IoCs detected.\n"
        if description:
            summary += f"{description[:150]}...\n" if len(description) > 150 else f"{description}\n"
        summary += "Security alert requires investigation and response.\n\n"

        summary += "**2. IMMEDIATE MITIGATION REQUIRED:**\n"
        summary += f"{'YES' if severity in ['high', 'critical'] else 'REVIEW REQUIRED'}\n\n"

        summary += "**3. RECOMMENDED PLAYBOOK:**\n"
        summary += "General Incident Response - Review alert details and apply appropriate security procedures"

        return summary
