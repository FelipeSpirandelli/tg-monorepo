import asyncio
from contextlib import AsyncExitStack
from typing import Optional

from anthropic import Anthropic
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from src.logger import logger


class MCPClient:
    def __init__(self):
        # Initialize session and client objects
        self.session: Optional[ClientSession] = None
        self.exit_stack = AsyncExitStack()
        self.anthropic = Anthropic()

    async def connect_to_server(self, server_script_path: str, timeout: int = 10):
        """Connect to an MCP server

        Args:
            server_script_path: Path to the server script (.py or .js)
            timeout: Maximum time in seconds to wait for initialization
        """
        is_python = server_script_path.endswith(".py")
        is_js = server_script_path.endswith(".js")
        if not (is_python or is_js):
            raise ValueError("Server script must be a .py or .js file")

        command = "python" if is_python else "node"
        logger.info(f"Connecting to server using command: {command} {server_script_path}")
        server_params = StdioServerParameters(command=command, args=[server_script_path], env=None)

        try:
            stdio_transport = await self.exit_stack.enter_async_context(stdio_client(server_params))
            self.stdio, self.write = stdio_transport
            self.session = await self.exit_stack.enter_async_context(ClientSession(self.stdio, self.write))

            logger.info("Session created, initializing...")
            # Add timeout to the initialization step
            try:
                await asyncio.wait_for(self.session.initialize(), timeout=timeout)
                logger.info("Connected to server successfully")

                # List available tools
                response = await self.session.list_tools()
                tools = response.tools

                logger.info(f"Connected to server with tools: {[tool.name for tool in tools]}")
            except asyncio.TimeoutError:
                logger.error(f"Server initialization timed out after {timeout} seconds")
                await self.cleanup()
                raise ConnectionError(
                    f"Failed to initialize connection to MCP server: timeout after {timeout} seconds"
                )

        except Exception as e:
            logger.error(f"Error connecting to server: {str(e)}")
            await self.cleanup()
            raise ConnectionError(f"Failed to connect to MCP server: {str(e)}")

    async def process_query(
        self,
        query: str,
        model: str = "claude-3-5-sonnet-20241022",
        max_tokens: int = 1000,
        temperature: float = 0.5,
    ) -> str:
        """Process a query using Claude and available tools

        Args:
            query: The user prompt to send to the model
            model: The model to use for the query
            max_tokens: Maximum number of tokens in the response
            temperature: Temperature for response generation (0.0-1.0)

        Returns:
            The model's response as a string
        """
        messages = [{"role": "user", "content": query}]

        response = await self.session.list_tools()
        available_tools = [
            {"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema}
            for tool in response.tools
        ]

        # Initial Claude API call
        response = self.anthropic.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=messages,
            tools=available_tools,
        )

        # Process response and handle tool calls
        final_text = []

        assistant_message_content = []
        for content in response.content:
            if content.type == "text":
                final_text.append(content.text)
                assistant_message_content.append(content)
            elif content.type == "tool_use":
                tool_name = content.name
                tool_args = content.input

                # Execute tool call
                result = await self.session.call_tool(tool_name, tool_args)
                final_text.append(f"[Calling tool {tool_name} with args {tool_args}]")

                assistant_message_content.append(content)
                messages.append({"role": "assistant", "content": assistant_message_content})
                messages.append(
                    {
                        "role": "user",
                        "content": [
                            {"type": "tool_result", "tool_use_id": content.id, "content": result.content}
                        ],
                    }
                )

                # Get next response from Claude
                response = self.anthropic.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=1000,
                    messages=messages,
                    tools=available_tools,
                )

                final_text.append(response.content[0].text)

        return "\n".join(final_text)

    async def cleanup(self):
        """Clean up resources"""
        await self.exit_stack.aclose()
