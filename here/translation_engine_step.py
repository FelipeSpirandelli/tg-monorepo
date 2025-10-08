import json
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
            logger.warning("LLM summary generation failed, using fallback")
            initial_summary = self._generate_template_summary(enriched_alert, extracted_iocs)
        
        logger.info("Translation engine completed - initial summary ready for LLM enhancement")
        
        return {
            "natural_language_summary": initial_summary,
            "analyst_ready_report": analyst_report
        }

    async def _generate_initial_summary(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Generate initial summary using LLM (without MCP tools)"""
        try:
            prompt = self._create_initial_summary_prompt(alert, iocs)
            
            response = await self.mcp_client.process_query(
                prompt,
                model="claude-3-7-sonnet-20250219",
                max_tokens=1500,
                temperature=0.3
            )
            
            logger.info("Successfully generated initial summary")
            return response
            
        except Exception as e:
            logger.error(f"Error generating initial summary: {str(e)}")
            return ""

    def _create_initial_summary_prompt(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Create prompt for initial summary (before MCP enhancement)"""
        
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        description = alert.get("rule_description", "")
        
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
            techniques = [f"{t.get('id', 'Unknown')} ({t.get('name', 'Unknown')})" for t in mitre_techniques[:3]]
            mitre_info = f"MITRE ATT&CK Techniques: {', '.join(techniques)}"
        
        prompt = f"""You are a cybersecurity analyst creating an initial alert summary.

SECURITY ALERT DETAILS:
- Rule: {rule_name}
- Severity: {severity.upper()}
- Description: {description}
{mitre_info}

EXTRACTED INDICATORS OF COMPROMISE:
{chr(10).join(ioc_summary) if ioc_summary else "- No significant IoCs extracted"}
Total IoCs: {total_iocs}

Create a comprehensive professional security alert analysis that includes:

**SECTION 1: Incident Overview (2-3 paragraphs)**
1. Detailed explanation of what type of security event this is
2. Complete threat analysis based on the rule description and IoCs
3. MITRE ATT&CK framework context and implications
4. Risk assessment and potential impact

**SECTION 2: Technical Analysis (2-3 paragraphs)**
1. Detailed breakdown of all indicators of compromise
2. Analysis of attack patterns and techniques observed
3. Network communication analysis (if applicable)
4. Timeline and sequence of events (if discernible)

**SECTION 3: Immediate Assessment (1-2 paragraphs)**
1. Urgency level and criticality assessment
2. Key indicators requiring immediate investigation
3. Initial containment considerations
4. Preliminary recommendations for SOC analysts

Write in detailed professional security analyst language. Provide comprehensive analysis while being clear that this is initial assessment before threat intelligence enhancement.

This summary should be thorough enough to stand alone as a preliminary incident report."""

        return prompt

    def _create_initial_analyst_report(self, alert: dict[str, Any], iocs: dict[str, list]) -> dict[str, Any]:
        """Create initial analyst report structure"""
        
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        total_iocs = sum(len(values) for values in iocs.values())
        
        return {
            "executive_summary": f"Security alert '{rule_name}' triggered with {severity} severity, {total_iocs} IoCs identified",
            "alert_details": {
                "rule_name": rule_name,
                "severity": severity,
                "total_iocs": total_iocs,
                "mitre_techniques": [t.get('id') for t in alert.get('mitre_techniques', [])],
            },
            "ioc_breakdown": {k: len(v) for k, v in iocs.items() if v},
            "status": "initial_analysis",
            "needs_enhancement": True,
            "enhancement_note": "This report will be enhanced with threat intelligence via MCP tools"
        }

    def _generate_template_summary(self, alert: dict[str, Any], iocs: dict[str, list]) -> str:
        """Generate template-based fallback summary"""
        
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        total_iocs = sum(len(values) for values in iocs.values())
        
        summary = f"SECURITY ALERT: {rule_name}\n\n"
        summary += f"A {severity} severity security alert has been triggered. "
        summary += f"Initial analysis identified {total_iocs} indicators of compromise "
        summary += f"that require further investigation.\n\n"
        
        # Add IoC breakdown
        if total_iocs > 0:
            summary += "Key indicators identified:\n"
            for ioc_type, values in iocs.items():
                if values:
                    summary += f"- {ioc_type.replace('_', ' ').title()}: {len(values)}\n"
        
        summary += "\nThis alert requires analyst review and threat intelligence enhancement."
        
        return summary

    async def _generate_llm_report(self, context: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        """Generate structured analyst report using LLM"""
        try:
            prompt = self._create_report_prompt(context, alert)
            
            response = await self.mcp_client.process_query(
                prompt,
                model="claude-3-7-sonnet-20250219",  # Using working model
                max_tokens=3000,
                temperature=0.3  # Focused for structured output
            )
            
            # Parse JSON response
            report = self._parse_llm_report_response(response)
            
            # Add metadata
            report["alert_metadata"] = self._extract_metadata(alert)
            report["generation_timestamp"] = self._get_current_timestamp()
            
            logger.info("Successfully generated LLM report")
            return report
            
        except Exception as e:
            logger.error(f"Error generating LLM report: {str(e)}")
            return {}

    def _create_summary_prompt(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Create prompt for generating natural language summary"""
        
        # Extract key information
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        ioc_summary = alert.get("ioc_summary", {})
        contextualized_analysis = context.get("contextualized_analysis", "")
        
        # Build context summary
        context_highlights = []
        
        # IP reputation findings
        ip_reputation = context.get("ip_reputation", {})
        malicious_ips = [ip for ip, info in ip_reputation.items() 
                        if isinstance(info, dict) and info.get("reputation") == "malicious"]
        if malicious_ips:
            context_highlights.append(f"Malicious IPs detected: {', '.join(malicious_ips[:3])}")
        
        # Threat level
        threat_level = context.get("overall_threat_level", "unknown")
        if threat_level != "unknown":
            context_highlights.append(f"Threat level assessed as: {threat_level}")
        
        # Threat assessments
        threat_assessments = context.get("threat_assessments", [])
        if threat_assessments and isinstance(threat_assessments[0], dict):
            recommended_action = threat_assessments[0].get("recommended_action", "").replace("_", " ")
            if recommended_action:
                context_highlights.append(f"Recommended action: {recommended_action}")
        
        prompt = f"""You are a senior SOC analyst writing a comprehensive security alert summary for your team.

ALERT INFORMATION:
- Rule: {rule_name}
- Severity: {severity}
- IoCs Found: {ioc_summary.get('total_iocs', 0)} total indicators
- MITRE Techniques: {[t.get('name', t.get('id', '')) for t in alert.get('mitre_techniques', [])]}

THREAT INTELLIGENCE CONTEXT:
{chr(10).join(f"- {highlight}" for highlight in context_highlights) if context_highlights else "- No significant threat intelligence findings"}

CONTEXTUALIZED ANALYSIS:
{contextualized_analysis if contextualized_analysis else "No additional context analysis available."}

Your task is to write a comprehensive, natural language summary that:

1. **Explains what happened** in clear terms that both technical and non-technical stakeholders can understand
2. **Describes the threat significance** and why this alert matters
3. **Provides context** about the threat landscape and attack patterns
4. **Highlights key findings** from the IoC and threat intelligence analysis
5. **Explains the impact** and potential consequences if not addressed

Write this as a flowing narrative (3-4 paragraphs) that tells the story of this security event. Use professional but accessible language. Focus on providing actionable insights rather than just listing technical details.

Start with what type of security event this is and why it triggered an alert, then build the narrative around the evidence and threat intelligence findings."""

        return prompt

    def _create_report_prompt(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Create prompt for generating structured analyst report"""
        
        # Convert context and alert to JSON for the prompt
        context_json = json.dumps(context, indent=2, default=str)
        alert_summary = {
            "rule_name": alert.get("rule_name"),
            "severity": alert.get("severity"),
            "timestamp": alert.get("timestamp"),
            "mitre_techniques": alert.get("mitre_techniques", []),
            "ioc_summary": alert.get("ioc_summary", {}),
            "extracted_iocs": alert.get("extracted_iocs", {})
        }
        alert_json = json.dumps(alert_summary, indent=2, default=str)
        
        prompt = f"""You are a cybersecurity analyst creating a structured incident report for SOC operations.

ALERT DATA:
{alert_json}

THREAT INTELLIGENCE CONTEXT:
{context_json}

Generate a structured report in JSON format with the following sections:

{{
    "executive_summary": "Brief 1-2 sentence overview of the alert",
    "threat_analysis": "Detailed analysis of the threat level, attack vectors, and tactics",
    "ioc_analysis": "Analysis of the indicators of compromise and their significance",
    "risk_assessment": "Assessment of potential impact and risk factors",
    "immediate_actions": ["list", "of", "immediate_actions_needed"],
    "investigation_steps": ["list", "of", "investigation_steps"],
    "prevention_measures": ["list", "of", "prevention_recommendations"],
    "key_findings": ["list", "of", "most_important_discoveries"],
    "confidence_level": "high/medium/low confidence in the analysis"
}}

Guidelines:
- Make each section actionable and specific
- Focus on practical next steps for SOC analysts
- Include threat intelligence context in your analysis
- Prioritize findings based on risk and evidence strength
- Use clear, professional language
- Base recommendations on the MITRE ATT&CK framework when applicable

Respond with ONLY the JSON object, no additional formatting or text."""

        return prompt

    def _parse_llm_report_response(self, response: str) -> dict[str, Any]:
        """Parse LLM response to extract structured report"""
        try:
            # Find JSON in response
            json_start = response.find('{')
            json_end = response.rfind('}')
            
            if json_start != -1 and json_end != -1:
                json_str = response[json_start:json_end + 1]
                report = json.loads(json_str)
                
                # Ensure required fields exist
                required_fields = [
                    "executive_summary", "threat_analysis", "ioc_analysis", 
                    "risk_assessment", "immediate_actions", "investigation_steps",
                    "prevention_measures", "key_findings", "confidence_level"
                ]
                
                for field in required_fields:
                    if field not in report:
                        report[field] = "Not available" if field not in ["immediate_actions", "investigation_steps", "prevention_measures", "key_findings"] else []
                
                return report
            else:
                logger.warning("No JSON found in LLM report response")
                return {}
                
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM report JSON: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"Error parsing LLM report response: {str(e)}")
            return {}

    def _generate_fallback_summary(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Generate fallback summary using template-based approach"""
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium")
        threat_level = context.get("overall_threat_level", "unknown")
        
        summary = f"Security Alert: {rule_name} (Severity: {severity.upper()})\n\n"
        summary += f"A {severity} severity security alert has been triggered by the rule '{rule_name}'. "
        
        if threat_level != "unknown":
            summary += f"Threat intelligence analysis indicates a {threat_level} threat level. "
        
        # Add IoC information
        ioc_summary = alert.get("ioc_summary", {})
        total_iocs = ioc_summary.get("total_iocs", 0)
        if total_iocs > 0:
            summary += f"Analysis identified {total_iocs} indicators of compromise requiring investigation. "
        
        # Add context information
        contextualized_analysis = context.get("contextualized_analysis", "")
        if contextualized_analysis:
            summary += f"\n\nThreat Intelligence Context:\n{contextualized_analysis}"
        
        summary += f"\n\nThis alert requires analyst review and appropriate response based on organizational security policies."
        
        return summary

    def _generate_fallback_report(self, context: dict[str, Any], alert: dict[str, Any]) -> dict[str, Any]:
        """Generate fallback report using template-based approach"""
        return {
            "executive_summary": f"Security alert triggered by {alert.get('rule_name', 'unknown rule')} with {alert.get('severity', 'medium')} severity",
            "threat_analysis": f"Threat level assessed as {context.get('overall_threat_level', 'unknown')} based on available intelligence",
            "ioc_analysis": f"Found {alert.get('ioc_summary', {}).get('total_iocs', 0)} indicators of compromise requiring analysis",
            "risk_assessment": f"Risk level corresponds to {alert.get('severity', 'medium')} severity classification",
            "immediate_actions": ["Review alert details", "Analyze identified IoCs", "Assess threat level"],
            "investigation_steps": ["Examine network logs", "Check for lateral movement", "Validate threat intelligence"],
            "prevention_measures": ["Update security rules", "Enhance monitoring", "Review security policies"],
            "key_findings": ["Security rule triggered", "IoCs identified", "Threat assessment completed"],
            "confidence_level": "medium",
            "alert_metadata": self._extract_metadata(alert),
            "generation_timestamp": self._get_current_timestamp()
        }
    
    def _generate_alert_summary(self, alert: dict[str, Any]) -> str:
        """Generate a concise summary of the alert"""
        rule_name = alert.get("rule_name", "Unknown Rule")
        severity = alert.get("severity", "medium").upper()
        timestamp = alert.get("timestamp", "unknown time")
        action_group = alert.get("action_group_name", "general security event")
        
        # Count IoCs
        ioc_counts = alert.get("ioc_summary", {}).get("ioc_counts", {})
        total_iocs = sum(ioc_counts.values())
        
        summary = f"""SECURITY ALERT: {rule_name}
        
Severity: {severity}
Time: {timestamp}
Category: {action_group}
Indicators Found: {total_iocs} IoCs identified"""
        
        # Add MITRE ATT&CK context if available
        mitre_techniques = alert.get("mitre_techniques", [])
        if mitre_techniques:
            technique_names = [t.get("name", "Unknown") for t in mitre_techniques[:2]]
            summary += f"\nMITRE ATT&CK Techniques: {', '.join(technique_names)}"
        
        return summary
    
    def _generate_threat_analysis(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Generate threat analysis narrative"""
        threat_level = context.get("overall_threat_level", "unknown")
        
        analysis = f"THREAT LEVEL: {threat_level.upper()}\n\n"
        
        # Analyze threat assessments
        assessments = context.get("threat_assessments", [])
        if assessments and isinstance(assessments[0], dict):
            assessment = assessments[0]
            
            if "threat_score" in assessment:
                score = assessment["threat_score"]
                analysis += f"Calculated threat score: {score}/100\n"
            
            if "recommended_action" in assessment:
                action = assessment["recommended_action"].replace("_", " ").title()
                analysis += f"Recommended action: {action}\n"
            
            # Explain factors
            factors = assessment.get("factors_considered", {})
            if factors:
                analysis += "\nFactors considered in this assessment:\n"
                for factor, considered in factors.items():
                    if considered:
                        factor_name = factor.replace("_", " ").title()
                        analysis += f"• {factor_name}\n"
        
        # Add historical context
        historical = context.get("historical_patterns", [])
        if historical and isinstance(historical[0], dict) and "similar_incidents" in historical[0]:
            similar_count = historical[0]["similar_incidents"]
            if similar_count > 0:
                analysis += f"\nHistorical context: {similar_count} similar incidents detected in the past week."
            else:
                analysis += "\nHistorical context: This appears to be a novel attack pattern."
        
        return analysis
    
    def _generate_ioc_analysis(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Generate analysis of Indicators of Compromise"""
        analysis = "INDICATORS OF COMPROMISE ANALYSIS\n\n"
        
        # Analyze IP addresses
        ip_reputation = context.get("ip_reputation", {})
        if ip_reputation:
            analysis += "IP Address Analysis:\n"
            for ip, info in ip_reputation.items():
                if isinstance(info, dict) and "reputation" in info:
                    reputation = info["reputation"]
                    country = info.get("country", "Unknown")
                    
                    if reputation == "malicious":
                        analysis += f"• {ip} - MALICIOUS (Location: {country})\n"
                        threat_types = info.get("threat_types", [])
                        if threat_types:
                            analysis += f"  Associated with: {', '.join(threat_types)}\n"
                        
                        campaigns = info.get("malware_campaigns", [])
                        if campaigns:
                            analysis += f"  Linked to campaigns: {', '.join(campaigns)}\n"
                    
                    elif reputation == "suspicious":
                        analysis += f"• {ip} - Suspicious activity (Location: {country})\n"
                        threat_types = info.get("threat_types", [])
                        if threat_types:
                            analysis += f"  Recent activity: {', '.join(threat_types)}\n"
                    
                    elif reputation == "private":
                        analysis += f"• {ip} - Internal/Private network address\n"
                    
                    else:
                        analysis += f"• {ip} - Clean reputation (Location: {country})\n"
            analysis += "\n"
        
        # Analyze domains
        domain_reputation = context.get("domain_reputation", {})
        if domain_reputation:
            analysis += "Domain Analysis:\n"
            for domain, info in domain_reputation.items():
                if isinstance(info, dict) and "reputation" in info:
                    reputation = info["reputation"]
                    if reputation == "suspicious":
                        analysis += f"• {domain} - Suspicious domain\n"
                        if info.get("phishing_detected"):
                            analysis += f"  Potential phishing activity detected\n"
                        if info.get("malware_associations"):
                            analysis += f"  Malware associations: {', '.join(info['malware_associations'])}\n"
                    else:
                        analysis += f"• {domain} - {reputation.title()}\n"
            analysis += "\n"
        
        # Analyze ports
        port_analysis = context.get("port_analysis", {})
        if port_analysis and isinstance(port_analysis, dict):
            suspicious_ports = port_analysis.get("suspicious_ports", 0)
            if suspicious_ports > 0:
                analysis += f"Port Analysis:\n"
                analysis += f"• {suspicious_ports} suspicious ports detected\n"
                common_threats = port_analysis.get("common_threats", [])
                if common_threats:
                    analysis += f"• Common threats on these ports: {', '.join(common_threats)}\n"
                analysis += "\n"
        
        return analysis
    
    def _generate_risk_assessment(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Generate risk assessment and impact analysis"""
        assessment = "RISK ASSESSMENT\n\n"
        
        # Overall risk level
        threat_level = context.get("overall_threat_level", "unknown")
        severity = alert.get("severity", "medium")
        
        assessment += f"Alert Severity: {severity.upper()}\n"
        assessment += f"Calculated Threat Level: {threat_level.upper()}\n\n"
        
        # Risk factors
        assessment += "Risk Factors:\n"
        
        # Check for malicious IPs
        malicious_ips = sum(
            1 for info in context.get("ip_reputation", {}).values()
            if isinstance(info, dict) and info.get("reputation") == "malicious"
        )
        if malicious_ips > 0:
            assessment += f"• {malicious_ips} known malicious IP(s) involved\n"
        
        # Check for suspicious domains
        suspicious_domains = sum(
            1 for info in context.get("domain_reputation", {}).values()
            if isinstance(info, dict) and info.get("reputation") == "suspicious"
        )
        if suspicious_domains > 0:
            assessment += f"• {suspicious_domains} suspicious domain(s) detected\n"
        
        # Check MITRE techniques
        mitre_techniques = alert.get("mitre_techniques", [])
        if mitre_techniques:
            assessment += f"• Attack techniques identified: {len(mitre_techniques)} MITRE ATT&CK techniques\n"
        
        # Potential impact
        assessment += "\nPotential Impact:\n"
        if threat_level == "critical":
            assessment += "• CRITICAL: Immediate action required to prevent data loss or system compromise\n"
        elif threat_level == "high":
            assessment += "• HIGH: Urgent investigation needed to prevent escalation\n"
        elif threat_level == "medium":
            assessment += "• MEDIUM: Scheduled investigation recommended\n"
        else:
            assessment += "• LOW: Monitoring and routine investigation sufficient\n"
        
        return assessment
    
    def _generate_recommendations(self, context: dict[str, Any], alert: dict[str, Any]) -> str:
        """Generate actionable recommendations"""
        recommendations = "RECOMMENDED ACTIONS\n\n"
        
        # Immediate actions based on threat level
        threat_level = context.get("overall_threat_level", "unknown")
        
        recommendations += "Immediate Actions:\n"
        if threat_level in ["critical", "high"]:
            recommendations += "1. Escalate to senior analyst immediately\n"
            recommendations += "2. Consider isolating affected systems\n"
            
            # IP-specific actions
            malicious_ips = [
                ip for ip, info in context.get("ip_reputation", {}).items()
                if isinstance(info, dict) and info.get("reputation") == "malicious"
            ]
            if malicious_ips:
                recommendations += f"3. Block traffic from IPs: {', '.join(malicious_ips[:3])}\n"
        
        elif threat_level == "medium":
            recommendations += "1. Assign to analyst for investigation within 4 hours\n"
            recommendations += "2. Monitor affected systems for additional activity\n"
        else:
            recommendations += "1. Log for routine analysis\n"
            recommendations += "2. Monitor for pattern development\n"
        
        # Investigation steps
        recommendations += "\nInvestigation Steps:\n"
        
        ioc_counts = alert.get("ioc_summary", {}).get("ioc_counts", {})
        if ioc_counts.get("ip_addresses", 0) > 0:
            recommendations += "• Analyze network logs for additional connections from identified IPs\n"
        
        if ioc_counts.get("file_hashes", 0) > 0:
            recommendations += "• Submit file hashes to malware analysis sandbox\n"
        
        if ioc_counts.get("processes", 0) > 0:
            recommendations += "• Review process execution logs on affected systems\n"
        
        if alert.get("mitre_techniques"):
            recommendations += "• Cross-reference MITRE ATT&CK techniques with organizational defenses\n"
        
        # Prevention measures
        recommendations += "\nPrevention Measures:\n"
        recommendations += "• Update security rules based on identified attack patterns\n"
        recommendations += "• Review and strengthen monitoring for similar attack vectors\n"
        
        if context.get("ip_reputation"):
            recommendations += "• Consider adding identified malicious IPs to blocklist\n"
        
        return recommendations
    
    def _build_comprehensive_summary(
        self, 
        alert_summary: str, 
        threat_analysis: str, 
        ioc_analysis: str, 
        risk_assessment: str, 
        recommendations: str
    ) -> str:
        """Build the comprehensive natural language summary"""
        
        summary = f"""{alert_summary}

{threat_analysis}

{ioc_analysis}

{risk_assessment}

{recommendations}

---
Generated by Agent Orchestrator - Rule-to-Text Pipeline
Analysis completed at: {self._get_current_timestamp()}"""
        
        return summary
    
    def _extract_metadata(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Extract key metadata for the analyst report"""
        return {
            "alert_id": alert.get("alert_id"),
            "rule_id": alert.get("rule_id"),
            "severity": alert.get("severity"),
            "risk_score": alert.get("risk_score"),
            "timestamp": alert.get("timestamp"),
            "total_iocs": alert.get("ioc_summary", {}).get("total_iocs", 0),
            "threat_level": alert.get("ioc_context", {}).get("overall_threat_level"),
        }
    
    def _get_current_timestamp(self) -> str:
        """Get current timestamp for report generation"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
