import logging
import sys

from mcp.server.fastmcp import FastMCP

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("mcp-api")

# Create an MCP server with more verbose output
mcp = FastMCP("TG-MCP-API", verbose=True)

logger.debug("Server starting up...")


# Add an addition tool
@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    logger.debug(f"Adding {a} and {b}")
    return a + b


# Add a dynamic greeting resource
@mcp.resource("greeting://{name}")
def get_greeting(name: str) -> str:
    """Get a personalized greeting"""
    logger.debug(f"Generating greeting for {name}")
    return f"Hello, {name}!"


if __name__ == "__main__":
    logger.debug("Starting server...")
    # Make sure we flush stdout for proper communication
    sys.stdout.flush()
    mcp.run()
