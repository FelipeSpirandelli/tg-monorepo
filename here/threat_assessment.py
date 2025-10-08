from typing import Any

from src.logger import logger

from .ip_lookup import ip_lookup
from .port_analyzer import port_analyzer


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
        
        # Handle both old format and new AbuseIPDB format
        if "data" in ip_info:
            # New AbuseIPDB format
            data = ip_info["data"]
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            
            if abuse_score >= 75 or total_reports >= 10:
                base_score += 20  # Malicious
            elif abuse_score >= 25 or total_reports >= 1:
                base_score += 10  # Suspicious
        else:
            # Legacy format (fallback/mock)
            reputation = ip_info.get("reputation", "clean")
            if reputation == "malicious":
                base_score += 20
            elif reputation == "suspicious":
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
            "ip_reputation_checked": source_ip is not None,
            "port_analysis_performed": ports is not None,
        },
    }
