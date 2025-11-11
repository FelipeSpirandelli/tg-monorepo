from typing import Any

from mcp.server.fastmcp import FastMCP

from src.logger import logger

from .historical_data import historical_data
from .ip_lookup import ip_lookup
from .math_tools import add
from .playbook_rag import (
    get_available_playbooks,
    search_playbook_by_topic,
    search_playbooks,
)
from .port_analyzer import port_analyzer
from .threat_assessment import threat_assessment

# Create an MCP server instance for tools
mcp_tools = FastMCP("TG-Agent-Tools")


@mcp_tools.tool()
def add_numbers(a: int, b: int) -> int:
    """Add two numbers"""
    return add(a, b)


@mcp_tools.tool()
async def lookup_ip(ip_address: str) -> dict[str, Any]:
    """
    Look up reputation and geolocation data for an IP address using AbuseIPDB

    Args:
        ip_address: The IP address to look up

    Returns:
        Dictionary containing IP information including reputation and location
    """
    from .ip_lookup import _async_ip_lookup
    return await _async_ip_lookup(ip_address)


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


@mcp_tools.tool()
def search_playbook_knowledge(
    query: str, top_k: int = 5, filter_playbook: str | None = None
) -> dict[str, Any]:
    """
    Search for relevant playbook knowledge using semantic search against the RAG system

    Args:
        query: Natural language query to search for relevant playbook content
        top_k: Maximum number of results to return (default: 5)
        filter_playbook: Optional specific playbook document ID to search within

    Returns:
        Dictionary containing search results with playbook sections and metadata
    """
    return search_playbooks(query, top_k, filter_playbook)


@mcp_tools.tool()
def search_security_playbooks_by_topic(topic: str, top_k: int = 3) -> dict[str, Any]:
    """
    Search for playbooks related to a specific security incident type or topic

    Args:
        topic: Security topic or incident type (e.g., "malware", "phishing", "data breach", "DDoS")
        top_k: Number of most relevant results to return (default: 3)

    Returns:
        Dictionary containing relevant playbook sections for the security topic
    """
    return search_playbook_by_topic(topic, top_k)


@mcp_tools.tool()
def get_available_security_playbooks() -> dict[str, Any]:
    """
    Get a list of all available security playbooks in the RAG system

    Returns:
        Dictionary containing list of available playbook documents with metadata
    """
    return get_available_playbooks()


@mcp_tools.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    logger.debug(f"Generating greeting for {name}")
    return f"Hello, {name}!"


def get_mcp_tools_instance():
    """Get the MCP tools instance for integration with the agent"""
    return mcp_tools
