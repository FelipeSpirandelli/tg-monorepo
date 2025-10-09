import importlib.util
import os
import sys
from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors import PipelineProcessor


class AgentManager:
    def __init__(self):
        self.agents = {}
        self.pipeline_processor = PipelineProcessor()
        self.mcp_client = None

    async def initialize_mvc_agent(self):
        """Initialize the MVC agent with integrated MCP client"""
        try:
            # Create an integrated MCP client (no external server needed)
            logger.info("Initializing MVC agent with integrated tools...")
            self.mcp_client = IntegratedMCPClient()
            logger.info("Integrated MCP client initialized successfully")
            self.register_pipeline_steps()
            logger.info("MVC agent initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize MVC agent: {str(e)}")
            raise

    def register_pipeline_steps(self):
        """Register available pipeline steps"""
        from .processors import (
            AlertProcessingStep,
            IoCExtractorStep,
            LLMChatStep,
            MCPQueryStep,
            PromptGenerationStep,
            ResponseFormattingStep,
            TranslationEngineStep,
        )

        # Register standard pipeline steps
        self.pipeline_processor.register_step("alert_processing", AlertProcessingStep())
        self.pipeline_processor.register_step("prompt_generation", PromptGenerationStep())
        self.pipeline_processor.register_step("mcp_query", MCPQueryStep(self.mcp_client))
        self.pipeline_processor.register_step("response_formatting", ResponseFormattingStep())

        # Register Rule-to-Text pipeline steps (all require MCP client)
        self.pipeline_processor.register_step("ioc_extractor", IoCExtractorStep(self.mcp_client))
        self.pipeline_processor.register_step("translation_engine", TranslationEngineStep(self.mcp_client))
        self.pipeline_processor.register_step("llm_chat", LLMChatStep(self.mcp_client))

        # Try to load custom steps if available
        self._load_custom_steps()

    def _load_custom_steps(self):
        """Load custom pipeline steps from examples directory"""
        try:
            # Check if custom steps registration file exists
            custom_steps_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "../examples/register_custom_steps.py")
            )

            if os.path.exists(custom_steps_path):
                # Dynamically import the module
                spec = importlib.util.spec_from_file_location(
                    "register_custom_steps", custom_steps_path
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules["register_custom_steps"] = module
                    spec.loader.exec_module(module)

                    # Call the function to register custom steps
                    if hasattr(module, "register_custom_steps"):
                        module.register_custom_steps(self.pipeline_processor)
                        logger.info("Custom pipeline steps registered")
        except Exception as e:
            logger.error(f"Error loading custom pipeline steps: {str(e)}")

    def get_default_pipeline(self) -> list[str]:
        """Get the default pipeline (Rule-to-Text + LLM Pipeline)"""
        return [
            "alert_processing",      # Process raw alert data
            "ioc_extractor",         # Extract IoCs using LLM
            "translation_engine",    # Convert to initial natural language
            "llm_chat",             # Interactive LLM chat with playbook integration
            "prompt_generation",     # Generate prompt for final LLM analysis
            "mcp_query",            # LLM uses MCP tools for threat intel
            "response_formatting"    # Format final response
        ]

    def get_rule_to_text_pipeline(self) -> list[str]:
        """Get the Rule-to-Text pipeline only (first 2 steps + initial translation)"""
        return [
            "alert_processing",
            "ioc_extractor",
            "translation_engine"
        ]

    def get_llm_engine_pipeline(self) -> list[str]:
        """Get the LLM Engine pipeline (translation + interactive chat)"""
        return [
            "alert_processing",
            "ioc_extractor",
            "translation_engine",
            "llm_chat"
        ]

    def get_legacy_pipeline(self) -> list[str]:
        """Get the legacy pipeline (before Rule-to-Text implementation)"""
        return ["alert_processing", "prompt_generation", "mcp_query", "response_formatting"]

    async def process_alert(self, alert_data: dict[str, Any]) -> dict[str, Any]:
        """Process an alert through the pipeline"""
        try:
            # Get default pipeline
            pipeline = self.get_default_pipeline()

            # Process through pipeline
            result = await self.pipeline_processor.process(alert_data, pipeline)
            return result
        except Exception as e:
            logger.error(f"Error processing alert: {str(e)}")
            logger.error(f"Alert data: {alert_data}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    async def run_agent(self, agent_name: str, query: str) -> str:
        """Legacy method to run queries directly"""
        if agent_name != "mvc_agent" or not self.mcp_client:
            raise ValueError(f"Agent {agent_name} not available")

        response = await self.mcp_client.process_query(query)
        return response
