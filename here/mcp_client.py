from collections.abc import Callable
from typing import Any

from anthropic import Anthropic

from config import Config
from src.logger import logger
from src.tools import get_mcp_tools_instance


class IntegratedMCPClient:
    """MCP client that uses integrated tools instead of external server"""

    def __init__(self):
        self.anthropic = Anthropic(api_key=Config().api_key)
        self.mcp_tools = get_mcp_tools_instance()
        self.available_tools = []
        self._initialize_tools()

    def _initialize_tools(self):
        """Initialize available tools from the integrated MCP instance"""
        # Get tools from the MCP tools instance
        # Note: FastMCP doesn't expose tools directly, so we'll manually define them
        self.available_tools = [
            {
                "name": "add_numbers",
                "description": "Add two numbers",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "a": {"type": "integer", "description": "First number"},
                        "b": {"type": "integer", "description": "Second number"},
                    },
                    "required": ["a", "b"],
                },
            },
            {
                "name": "lookup_ip",
                "description": "Look up reputation and geolocation data for an IP address",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ip_address": {"type": "string", "description": "The IP address to look up"}
                    },
                    "required": ["ip_address"],
                },
            },
            {
                "name": "analyze_ports",
                "description": "Analyze if specific ports are commonly associated with threats",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "List of port numbers to analyze",
                        }
                    },
                    "required": ["ports"],
                },
            },
            {
                "name": "get_historical_data",
                "description": "Check if similar patterns have been seen before in historical data",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "signature": {
                            "type": "string",
                            "description": "The pattern signature to search for",
                        },
                        "timeframe_hours": {
                            "type": "integer",
                            "description": "How many hours back to search",
                            "default": 24,
                        },
                    },
                    "required": ["signature"],
                },
            },
            {
                "name": "assess_threat",
                "description": "Perform a comprehensive threat assessment based on alert data",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "alert_type": {"type": "string", "description": "Type of alert"},
                        "severity": {"type": "string", "description": "Alert severity level"},
                        "source_ip": {
                            "type": "string",
                            "description": "Source IP address if applicable",
                        },
                        "ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "List of ports involved if applicable",
                        },
                    },
                    "required": ["alert_type", "severity"],
                },
            },
        ]
        logger.info(f"Initialized with {len(self.available_tools)} integrated tools")

    async def process_query(
        self,
        query: str,
        model: str = "claude-3-5-haiku-20241022",  # Using working model
        max_tokens: int = 1000,
        temperature: float = 0.5,
    ) -> str:
        """
        Process a query using Claude and available integrated tools

        Args:
            query: The user prompt to send to the model
            model: The model to use for the query
            max_tokens: Maximum number of tokens in the response
            temperature: Temperature for response generation (0.0-1.0)

        Returns:
            The model's response as a string
        """
        messages: list[dict[str, str | list[dict[str, str]]]] = [{"role": "user", "content": query}]

        # Initial Claude API call
        response = self.anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=messages,
            tools=self.available_tools,
        )

        # Process response and handle tool calls
        final_text = []
        max_iterations = 5  # Prevent infinite loops

        for _ in range(max_iterations):
            assistant_message_content = []
            tool_calls_found = False

            for content in response.content:
                if content.type == "text":
                    final_text.append(content.text)
                    assistant_message_content.append(content)
                elif content.type == "tool_use":
                    tool_calls_found = True
                    assistant_message_content.append(content)

            # If no tool calls were found, we're done
            if not tool_calls_found:
                break

            # Add assistant message with tool calls
            messages.append({"role": "assistant", "content": assistant_message_content})

            # Execute tools and create tool results
            tool_results = []
            for content in assistant_message_content:
                if content.type == "tool_use":
                    tool_name = content.name
                    tool_args = content.input
                    result = await self._execute_tool(tool_name, tool_args)
                    final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")

                    tool_results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": content.id,
                            "content": str(result),
                        }
                    )

            # Add tool results message
            messages.append({"role": "user", "content": tool_results})

            # Get next response from Claude
            response = self.anthropic.messages.create(
                model=model,
                max_tokens=max_tokens,
                messages=messages,
                tools=self.available_tools,
            )

        return "\n".join(final_text)

    async def _execute_tool(self, tool_name: str, tool_args: dict):
        """Execute a tool call using the integrated MCP tools"""
        try:
            # Import the tool functions from tools module
            from .tools import (
                add,
                historical_data,
                ip_lookup,
                port_analyzer,
                threat_assessment,
            )

            # Define the type of tool functions
            tool_functions: dict[str, Callable[..., Any]] = {
                "add_numbers": add,
                "lookup_ip": ip_lookup,
                "analyze_ports": port_analyzer,
                "get_historical_data": historical_data,
                "assess_threat": threat_assessment,
            }

            if tool_name not in tool_functions:
                raise ValueError(f"Unknown tool: {tool_name}")

            # Execute the tool function
            result = tool_functions[tool_name](**tool_args)
            logger.debug(f"Tool {tool_name} executed successfully")
            return result

        except Exception as e:
            logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return {"error": f"Tool execution failed: {str(e)}"}

    async def cleanup(self):
        """Clean up resources (no external connections to close)"""
        logger.info("Integrated MCP client cleanup completed")
        pass
