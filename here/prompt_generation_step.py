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

    def _get_rule_to_text_prompt_template(self) -> str:
        """Get the Rule-to-Text prompt template for processed alerts"""
        return """
You are a senior cybersecurity analyst with access to threat intelligence tools. An initial security alert analysis has been completed, and now you need to enhance it with real-time threat intelligence.

## Initial Security Alert Analysis

{summary}

## Alert Metadata

{report[alert_details]}

## Available Indicators of Compromise

**Summary**: {report[ioc_breakdown]}

**Actual IoCs Extracted from Alert**:
{actual_iocs}

{tools_instruction}

**YOUR TASK:**
Use the available threat intelligence tools to enhance this analysis. Specifically:

1. **Lookup the ACTUAL IP addresses** listed above to check their reputation and threat associations
2. **Assess the overall threat level** based on the alert type, severity, and any malicious indicators found
3. **Check historical data** for similar attack patterns using the rule name or MITRE techniques
4. **Analyze any suspicious ports** if network activity is involved

After gathering this intelligence, provide a comprehensive enhanced analysis that includes:

- **Threat Assessment**: Overall risk level and confidence
- **Intelligence Findings**: What the tools revealed about the indicators
- **Attack Context**: How this fits into current threat landscape
- **Recommended Actions**: Specific steps based on the findings
- **Investigation Priorities**: What to focus on next

**CRITICAL INSTRUCTION**: You MUST use the tools first, then provide a detailed analysis. Do NOT stop after just calling tools!

**Step 1**: Use the tools to gather intelligence
**Step 2**: ANALYZE the tool results and provide comprehensive conclusions

After each tool provides results, you must interpret and analyze what those results mean for this security incident.

**MANDATORY**: After using all tools, provide a comprehensive final analysis that includes:

1. **Executive Summary** (2-3 sentences about the overall threat)
2. **Detailed Findings** (what each tool revealed, with specific data points)
3. **Threat Actor Analysis** (potential attribution, methods, sophistication level)
4. **Impact Assessment** (what systems/data are at risk)
5. **Immediate Actions** (specific steps to take right now)
6. **Investigation Playbook** (detailed next steps for analysts)
7. **Technical Details** (IP reputation scores, abuse confidence levels, port analysis)
8. **Timeline and Urgency** (how quickly this needs to be addressed)

Write a comprehensive 4-6 paragraph analysis that transforms the raw tool outputs into professional cybersecurity intelligence. Focus on actionable insights that help the SOC analyst understand the true nature and urgency of this security event.

**FINAL REQUIREMENT**: Your response MUST end with a detailed conclusion section that synthesizes all tool results into actionable intelligence. Do NOT simply list tool calls - provide actual analysis and conclusions!
"""
