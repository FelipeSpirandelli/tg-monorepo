from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors.pipeline_processor import PipelineStep


class RetrievalEngineStep(PipelineStep):
    """
    Retrieval Engine - Second step of Rule-to-Text pipeline
    
    Uses MCP calls to gather contextual information about extracted IoCs
    from cybersecurity databases and threat intelligence sources.
    """

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client

    @property
    def required_inputs(self) -> list[str]:
        return ["extracted_iocs", "enriched_alert"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["ioc_context", "enriched_alert_with_context"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Retrieve and analyze contextual information for extracted IoCs using LLM"""
        extracted_iocs = data["extracted_iocs"]
        enriched_alert = data["enriched_alert"]
        
        logger.info("Starting retrieval engine process with LLM analysis")
        
        # Initialize context storage
        ioc_context = {
            "ip_reputation": {},
            "domain_reputation": {},
            "threat_assessments": [],
            "historical_patterns": [],
            "port_analysis": {},
            "overall_threat_level": "unknown",
            "contextualized_analysis": ""
        }
        
        # Retrieve context for IP addresses using MCP tools

        # Use LLM to contextualize and correlate all gathered information
        contextualized_analysis = await self._contextualize_with_llm(
            enriched_alert, extracted_iocs, ioc_context
        )
        ioc_context["contextualized_analysis"] = contextualized_analysis
        
        # Create enriched alert with context
        enriched_alert_with_context = enriched_alert.copy()
        enriched_alert_with_context["ioc_context"] = ioc_context
        enriched_alert_with_context["context_summary"] = self._create_context_summary(ioc_context)
        
        logger.info(f"Retrieved and contextualized information for {len(extracted_iocs)} IoC types")
        
        return {
            "ioc_context": ioc_context,
            "enriched_alert_with_context": enriched_alert_with_context
        }
    
    
    async def _contextualize_with_llm(
        self, 
        alert: dict[str, Any], 
        iocs: dict[str, list], 
        context: dict[str, Any]
    ) -> str:
        """Use LLM to contextualize and correlate all gathered information"""
        try:
            logger.debug("Contextualizing threat intelligence with LLM")
            
            # Create prompt for LLM contextualization
            prompt = self._create_contextualization_prompt(alert, iocs, context)
            
            # Process with LLM
            response = await self.mcp_client.process_query(
                prompt,
                model="claude-sonnet-4-5-20250929",  # Using working model
                max_tokens=1500,
                temperature=0.3  # Slightly creative for analysis but still focused
            )
            
            logger.info("Successfully contextualized threat intelligence with LLM")
            return response
            
        except Exception as e:
            logger.error(f"Error in LLM contextualization: {str(e)}")
            return "Unable to generate LLM-based contextualization due to processing error."

    def _create_contextualization_prompt(
        self, 
        alert: dict[str, Any], 
        iocs: dict[str, list], 
        context: dict[str, Any]
    ) -> str:
        """Create prompt for LLM to contextualize threat intelligence"""
        
        # Extract key information for the prompt
        rule_name = alert.get("rule_name", "Unknown")
        severity = alert.get("severity", "medium")
        
        # Summarize IoCs
        ioc_summary = []
        for ioc_type, values in iocs.items():
            if values:
                count = len(values)
                ioc_summary.append(f"- {ioc_type}: {count} found ({values[:3] if count <= 3 else values[:3] + ['...']})")
        
        # Summarize context findings
        malicious_ips = []
        suspicious_ips = []
        for ip, info in context.get("ip_reputation", {}).items():
            if isinstance(info, dict):
                if info.get("reputation") == "malicious":
                    malicious_ips.append(ip)
                elif info.get("reputation") == "suspicious":
                    suspicious_ips.append(ip)
        
        threat_assessments = context.get("threat_assessments", [])
        threat_level = threat_assessments[0].get("threat_level", "unknown") if threat_assessments else "unknown"
        
        prompt = f"""You are a senior cybersecurity analyst specializing in threat intelligence correlation and contextual analysis.

SECURITY ALERT ANALYSIS REQUEST:

Alert Information:
- Rule: {rule_name}
- Severity: {severity}
- MITRE Techniques: {[t.get('id') for t in alert.get('mitre_techniques', [])]}

Extracted Indicators of Compromise:
{chr(10).join(ioc_summary) if ioc_summary else "- No significant IoCs extracted"}

Threat Intelligence Findings:
- Malicious IPs: {malicious_ips if malicious_ips else "None"}
- Suspicious IPs: {suspicious_ips if suspicious_ips else "None"}
- Overall Threat Level: {threat_level}

Your task is to provide a comprehensive contextual analysis that:

1. **Correlates the findings** - How do the IoCs, threat intelligence, and alert details relate to each other?

2. **Identifies attack patterns** - What attack techniques or campaigns might this represent based on the evidence?

3. **Assesses the threat landscape** - How does this fit into current threat trends and known attack vectors?

4. **Highlights key concerns** - What are the most significant risks and indicators that need immediate attention?

5. **Provides intelligence context** - What additional context from threat intelligence enhances understanding of this alert?

Please provide a detailed analysis in 2-3 paragraphs that would help a SOC analyst understand the broader context and significance of this security alert. Focus on actionable intelligence and clear explanations of the threat implications.

Do not repeat basic facts already available in the alert - instead, provide analytical insights and contextual intelligence that adds value to the investigation."""

        return prompt
    
    def _create_context_summary(self, context: dict[str, Any]) -> dict[str, Any]:
        """Create a summary of the retrieved context"""
        summary = {
            "total_ips_analyzed": len(context.get("ip_reputation", {})),
            "malicious_ips": 0,
            "suspicious_ips": 0,
            "total_domains_analyzed": len(context.get("domain_reputation", {})),
            "suspicious_domains": 0,
            "threat_level": context.get("overall_threat_level", "unknown"),
            "key_findings": []
        }
        
        # Count IP reputations
        for ip, info in context.get("ip_reputation", {}).items():
            if isinstance(info, dict) and "reputation" in info:
                if info["reputation"] == "malicious":
                    summary["malicious_ips"] += 1
                    summary["key_findings"].append(f"Malicious IP detected: {ip}")
                elif info["reputation"] == "suspicious":
                    summary["suspicious_ips"] += 1
                    summary["key_findings"].append(f"Suspicious IP detected: {ip}")
        
        # Count domain reputations
        for domain, info in context.get("domain_reputation", {}).items():
            if isinstance(info, dict) and info.get("reputation") == "suspicious":
                summary["suspicious_domains"] += 1
                summary["key_findings"].append(f"Suspicious domain detected: {domain}")
        
        # Add threat assessment findings
        for assessment in context.get("threat_assessments", []):
            if isinstance(assessment, dict) and "threat_level" in assessment:
                if assessment["threat_level"] in ["high", "critical"]:
                    summary["key_findings"].append(
                        f"High threat level detected: {assessment['threat_level']}"
                    )
        
        return summary
