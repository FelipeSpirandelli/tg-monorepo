from typing import Any

from mcp.server.fastmcp import FastMCP

from src.logger import logger

# Create an MCP server instance for tools
mcp_tools = FastMCP("TG-Agent-Tools", verbose=True)


@mcp_tools.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    logger.debug(f"Adding {a} and {b}")
    return a + b


@mcp_tools.tool()
def ip_lookup(ip_address: str) -> dict[str, Any]:
    """
    Look up reputation and geolocation data for an IP address

    Args:
        ip_address: The IP address to look up

    Returns:
        Dictionary containing IP information including reputation and location
    """
    logger.debug(f"Looking up IP address: {ip_address}")

    # Mock implementation - in reality, you'd call external APIs
    # like VirusTotal, AbuseIPDB, MaxMind, etc.
    return {
        "ip": ip_address,
        "reputation": "clean",  # Could be: clean, malicious, suspicious
        "country": "United States",
        "city": "San Francisco",
        "isp": "Example ISP",
        "threat_types": [],
        "confidence_score": 85,
    }


@mcp_tools.tool()
def port_analyzer(ports: list[int]) -> dict[str, Any]:
    """
    Analyze if specific ports are commonly associated with threats

    Args:
        ports: List of port numbers to analyze

    Returns:
        Dictionary containing port analysis information
    """
    logger.debug(f"Analyzing ports: {ports}")

    # Common threat-associated ports
    threat_ports = {
        22: {"service": "SSH", "threat_level": "medium", "notes": "Common brute force target"},
        23: {
            "service": "Telnet",
            "threat_level": "high",
            "notes": "Unencrypted, deprecated protocol",
        },
        3389: {"service": "RDP", "threat_level": "high", "notes": "Common ransomware entry point"},
        445: {
            "service": "SMB",
            "threat_level": "high",
            "notes": "Common malware propagation vector",
        },
        8080: {"service": "HTTP-Alt", "threat_level": "low", "notes": "Alternative HTTP port"},
    }

    analysis: dict[str, Any] = {
        "total_ports": len(ports),
        "suspicious_ports": 0,
        "port_details": [],
    }

    for port in ports:
        port_info = threat_ports.get(
            port,
            {"service": "Unknown", "threat_level": "low", "notes": "Standard or unknown service"},
        )

        if port_info["threat_level"] in ["high", "medium"]:
            analysis["suspicious_ports"] += 1

        analysis["port_details"].append({"port": port, **port_info})

    return analysis


@mcp_tools.tool()
def historical_data(signature: str, timeframe_hours: int = 24) -> dict[str, Any]:
    """
    Check if similar patterns have been seen before in historical data

    Args:
        signature: The pattern signature to search for
        timeframe_hours: How many hours back to search (default: 24)

    Returns:
        Dictionary containing historical pattern information
    """
    logger.debug(f"Searching historical data for signature: {signature}")

    # Mock implementation - in reality, you'd query your SIEM/database
    historical_matches = {
        "unusual_port_scan_pattern": 3,
        "suspicious_login_attempt": 15,
        "malware_communication": 0,
        "data_exfiltration": 1,
    }

    matches = historical_matches.get(signature, 0)

    return {
        "signature": signature,
        "timeframe_hours": timeframe_hours,
        "matches_found": matches,
        "trend": "increasing" if matches > 5 else "stable" if matches > 0 else "new",
        "last_seen": "2025-08-09T14:30:00Z" if matches > 0 else None,
        "similar_incidents": (
            [
                {"timestamp": "2025-08-09T14:30:00Z", "source": "172.16.254.2"},
                {"timestamp": "2025-08-09T12:15:00Z", "source": "172.16.254.3"},
            ]
            if matches > 0
            else []
        ),
    }


@mcp_tools.tool()
def threat_assessment(
    alert_type: str, severity: str, source_ip: str | None = None, ports: list[int] | None = None
) -> dict[str, Any]:
    """
    Perform a comprehensive threat assessment based on alert data

    Args:
        alert_type: Type of alert (e.g., 'security_alert', 'network_anomaly')
        severity: Alert severity level
        source_ip: Source IP address if applicable
        ports: List of ports involved if applicable

    Returns:
        Dictionary containing threat assessment results
    """
    logger.debug(f"Performing threat assessment for {alert_type} with severity {severity}")

    # Calculate base risk score
    severity_scores = {"low": 25, "medium": 50, "high": 75, "critical": 90}
    base_score = severity_scores.get(severity.lower(), 50)

    # Adjust score based on alert type
    if alert_type == "security_alert":
        base_score += 10
    elif alert_type == "network_anomaly":
        base_score += 5

    # Factor in IP reputation if provided
    if source_ip:
        ip_info = ip_lookup(source_ip)
        if ip_info["reputation"] == "malicious":
            base_score += 20
        elif ip_info["reputation"] == "suspicious":
            base_score += 10

    # Factor in port analysis if provided
    if ports:
        port_info = port_analyzer(ports)
        if port_info["suspicious_ports"] > 0:
            base_score += port_info["suspicious_ports"] * 5

    # Cap the score at 100
    final_score = min(base_score, 100)

    # Determine threat level
    if final_score >= 80:
        threat_level = "critical"
        recommended_action = "immediate_response"
    elif final_score >= 60:
        threat_level = "high"
        recommended_action = "urgent_investigation"
    elif final_score >= 40:
        threat_level = "medium"
        recommended_action = "scheduled_investigation"
    else:
        threat_level = "low"
        recommended_action = "monitoring"

    return {
        "threat_score": final_score,
        "threat_level": threat_level,
        "recommended_action": recommended_action,
        "factors_considered": {
            "base_severity": severity,
            "alert_type": alert_type,
            "ip_reputation": source_ip is not None,
            "port_analysis": ports is not None,
        },
    }


@mcp_tools.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    logger.debug(f"Generating greeting for {name}")
    return f"Hello, {name}!"


def get_mcp_tools_instance():
    """Get the MCP tools instance for integration with the agent"""
    return mcp_tools
