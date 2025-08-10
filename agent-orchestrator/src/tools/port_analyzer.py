from typing import Any

from src.logger import logger


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
