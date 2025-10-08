from typing import Any

from mcp.server.fastmcp import FastMCP

from src.logger import logger

from .historical_data import historical_data
from .ip_lookup import ip_lookup
from .math_tools import add
from .port_analyzer import port_analyzer
from .threat_assessment import threat_assessment

# Create an MCP server instance for tools
mcp_tools = FastMCP("TG-Agent-Tools")


@mcp_tools.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two numbers"""
    return add(a, b)


@mcp_tools.tool()
def lookup_ip(ip_address: str) -> dict[str, Any]:
    """
    Look up reputation and geolocation data for an IP address

    Args:
        ip_address: The IP address to look up

    Returns:
        Dictionary containing IP information including reputation and location
    """
    return ip_lookup(ip_address)


@mcp_tools.tool()
def analyze_ports(ports: list[int]) -> dict[str, Any]:
    """
    Analyze if specific ports are commonly associated with threats

    Args:
        ports: List of port numbers to analyze

    Returns:
        Dictionary containing port analysis information
    """
    return port_analyzer(ports)


@mcp_tools.tool()
def get_historical_data(signature: str, timeframe_hours: int = 24) -> dict[str, Any]:
    """
    Check if similar patterns have been seen before in historical data

    Args:
        signature: The pattern signature to search for
        timeframe_hours: How many hours back to search (default: 24)

    Returns:
        Dictionary containing historical pattern information
    """
    return historical_data(signature, timeframe_hours)


@mcp_tools.tool()
def assess_threat(
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
    return threat_assessment(alert_type, severity, source_ip, ports)


@mcp_tools.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    logger.debug(f"Generating greeting for {name}")
    return f"Hello, {name}!"


def get_mcp_tools_instance():
    """Get the MCP tools instance for integration with the agent"""
    return mcp_tools
