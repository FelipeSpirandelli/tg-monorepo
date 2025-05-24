import asyncio
import json
import os
import sys

import httpx
from src.logger import logger

# Add parent directory to path to import from src
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Example of an alert to send to the agent orchestrator
alert_data = {
    "alert_data": {
        "type": "security_alert",
        "source": "intrusion_detection_system",
        "severity": "high",
        "timestamp": "2025-05-24T15:30:45Z",
        "details": {
            "ip_address": "192.168.1.100",
            "event_id": "IDS-1234",
            "rule_triggered": "Suspicious Login Attempt",
            "attempts": 5,
            "user": "admin",
        },
    },
    # Optional pipeline configuration
    "pipeline_config": {
        "steps": ["alert_processing", "prompt_generation", "mcp_query", "response_formatting"],
        "step_config": {
            "prompt_generation": {
                "prompt_template": """
I received a security alert with the following information:
- Type: {alert[alert_type]}
- Source: {alert[source]}
- Severity: {alert[severity]}
- Timestamp: {alert[timestamp]}

Details:
IP Address: {alert[details][ip_address]}
Event ID: {alert[details][event_id]}
Rule Triggered: {alert[details][rule_triggered]}
Attempts: {alert[details][attempts]}
User: {alert[details][user]}

{tools_instruction}

Please analyze this security alert and recommend appropriate actions. 
Use the available tools to check if this is a known pattern and suggest remediation steps.
"""
            }
        },
    },
}


async def send_alert_to_orchestrator():
    """Example of sending an alert to the orchestrator"""
    async with httpx.AsyncClient() as client:
        response = await client.post("http://localhost:8001/alert", json=alert_data, timeout=30.0)

        if response.status_code == 200:
            result = response.json()
            logger.info("Alert processed successfully")
            logger.info(json.dumps(result, indent=2))
        else:
            logger.error(f"Error: {response.status_code}")
            logger.error(response.text)


if __name__ == "__main__":
    asyncio.run(send_alert_to_orchestrator())
