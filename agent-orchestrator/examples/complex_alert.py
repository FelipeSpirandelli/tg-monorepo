import asyncio
import json
import os
import sys
from typing import Any, Dict

import httpx
from src.logger import logger

# Add parent directory to path to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


# Example request with custom pipeline configuration
def create_complex_alert_request() -> Dict[str, Any]:
    """
    Create a complex alert request with custom pipeline configuration
    that specifies tool access instructions explicitly
    """
    return {
        "alert_data": {
            "type": "network_anomaly",
            "source": "traffic_analyzer",
            "severity": "medium",
            "timestamp": "2025-05-24T18:45:12Z",
            "details": {
                "source_ip": "172.16.254.1",
                "destination_ip": "203.0.113.5",
                "protocol": "TCP",
                "ports": [22, 23, 8080],
                "packet_count": 1500,
                "duration_seconds": 120,
                "signature": "unusual_port_scan_pattern",
            },
        },
        "pipeline_config": {
            # Custom pipeline that includes an alert enrichment step
            "steps": [
                "alert_processing",
                "alert_enrichment",  # This requires registering the custom step
                "prompt_generation",
                "mcp_query",
                "response_formatting",
            ],
            "step_config": {
                # Configuration for the prompt generation step
                "prompt_generation": {
                    "prompt_template": """
You are a cybersecurity analyst tasked with investigating a network anomaly.

ALERT DETAILS:
Type: {alert[alert_type]}
Source: {alert[source]}
Severity: {alert[severity]}
Timestamp: {alert[timestamp]}

NETWORK INFORMATION:
Source IP: {alert[details][source_ip]}
Destination IP: {alert[details][destination_ip]}
Protocol: {alert[details][protocol]}
Ports: {alert[details][ports]}
Packet Count: {alert[details][packet_count]}
Duration: {alert[details][duration_seconds]} seconds
Signature: {alert[details][signature]}

ENRICHMENT INFORMATION:
Risk Score: {enriched_alert[risk_score]}
Recommended Action: {enriched_alert[recommended_action]}

AVAILABLE TOOLS:
You have access to the following tools to help with your analysis:
1. ip_lookup - Look up reputation and geolocation data for an IP address
2. port_analyzer - Analyze if specific ports are commonly associated with threats
3. historical_data - Check if similar patterns have been seen before

Use these tools to perform a complete analysis of this network anomaly.
After using the tools, provide:
1. An assessment of the threat level
2. Recommended actions with justification
3. Any additional monitoring or investigation steps
"""
                },
                # Configuration specific to the MCP query step
                "mcp_query": {"model": "claude-3-5-sonnet-20241022", "max_tokens": 1500, "temperature": 0.2},
            },
        },
    }


async def send_complex_alert_to_orchestrator():
    """Send a complex alert to the orchestrator"""
    alert_data = create_complex_alert_request()

    async with httpx.AsyncClient() as client:
        response = await client.post("http://localhost:8001/alert", json=alert_data, timeout=60.0)

        if response.status_code == 200:
            result = response.json()
            logger.info("Complex alert processed successfully")
            logger.info(json.dumps(result, indent=2))
        else:
            logger.error(f"Error: {response.status_code}")
            logger.error(response.text)


if __name__ == "__main__":
    # Note: This example assumes you've registered the CustomAlertEnrichmentStep
    # from examples/custom_pipeline_step.py with the pipeline processor
    asyncio.run(send_complex_alert_to_orchestrator())
