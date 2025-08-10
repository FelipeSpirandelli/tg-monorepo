from typing import Any

from src.logger import logger


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
