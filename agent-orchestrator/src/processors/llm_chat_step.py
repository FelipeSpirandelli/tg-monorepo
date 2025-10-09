"""
llm_chat_step.py

LLM Chat Engine - Interactive chat step for SOC analyst communication
Allows back-and-forth conversation with LLM agent that can use tools like playbook_rag
"""

import asyncio
from typing import Any

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.processors.pipeline_processor import PipelineStep
from src.tools.playbook_rag import search_playbooks, get_available_playbooks


class LLMChatStep(PipelineStep):
    """
    LLM Chat Engine - Interactive chat step for SOC analyst communication

    This step enables interactive conversation between SOC analysts and the LLM agent.
    The LLM agent can use tools like playbook_rag to provide enhanced responses about alerts.
    """

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client

    @property
    def required_inputs(self) -> list[str]:
        return ["natural_language_summary", "analyst_ready_report"]

    @property
    def provided_outputs(self) -> list[str]:
        return ["llm_chat_summary", "conversation_history", "recommended_playbooks", "final_recommendations"]

    async def process(self, data: dict[str, Any]) -> dict[str, Any]:
        """Process alert through LLM chat session (automatic mode for pipeline)"""
        natural_language_summary = data["natural_language_summary"]
        analyst_ready_report = data["analyst_ready_report"]

        logger.info("Starting LLM Chat Engine - automatic mode for pipeline")

        # Initialize conversation with alert context
        conversation_history = await self._initialize_conversation(natural_language_summary, analyst_ready_report)

        # Get relevant playbooks for this alert
        recommended_playbooks = await self._find_relevant_playbooks(natural_language_summary)

        # Generate initial LLM response with playbook recommendations
        initial_response = await self._generate_initial_response(
            natural_language_summary, analyst_ready_report, recommended_playbooks, conversation_history
        )

        # Add initial response to conversation history
        conversation_history.append({"role": "assistant", "content": initial_response})

        # For pipeline mode, generate a summary response
        final_response = await self._generate_final_response(conversation_history, recommended_playbooks)

        logger.info("LLM Chat Engine completed - pipeline mode finished")

        return {
            "llm_chat_summary": final_response,
            "conversation_history": conversation_history,
            "recommended_playbooks": recommended_playbooks,
            "final_recommendations": self._extract_recommendations(final_response)
        }

    async def _initialize_conversation(self, summary: str, report: dict[str, Any]) -> list[dict[str, str]]:
        """Initialize conversation with alert context"""
        return [
            {
                "role": "system",
                "content": """You are an expert SOC analyst assistant with access to security playbooks and threat intelligence tools.

Your role is to help SOC analysts understand and respond to security alerts by:
1. Analyzing the alert details and providing clear explanations
2. Searching relevant security playbooks using available tools
3. Recommending specific response actions based on best practices
4. Answering follow-up questions and providing additional context

Always use the playbook_rag tool when recommending response procedures to ensure accuracy and completeness."""
            },
            {
                "role": "user",
                "content": f"""I need your help analyzing this security alert:

**Alert Summary:**
{summary}

**Analyst Report:**
{report.get('executive_summary', 'No executive summary available')}

Please provide:
1. A clear explanation of what this alert means
2. Recommended response procedures from relevant playbooks
3. Any immediate actions that should be taken
4. Additional investigation steps if needed

Use the available tools to search for relevant security playbooks."""
            }
        ]

    async def _find_relevant_playbooks(self, summary: str) -> list[dict[str, Any]]:
        """Find relevant playbooks for the alert"""
        try:
            # Extract key terms from summary for better search
            search_terms = self._extract_search_terms(summary)

            # Search for relevant playbooks
            search_results = []
            for term in search_terms:
                results = search_playbooks(f"security incident response playbook for {term}", top_k=3)
                if results.get("success", False):
                    search_results.extend(results.get("results", []))

            # Remove duplicates and sort by relevance
            unique_playbooks = {}
            for result in search_results:
                playbook_name = result.get("playbook", "")
                if playbook_name not in unique_playbooks:
                    unique_playbooks[playbook_name] = result

            return list(unique_playbooks.values())

        except Exception as e:
            logger.error(f"Error finding relevant playbooks: {str(e)}")
            return []

    async def _generate_initial_response(self, summary: str, report: dict[str, Any],
                                       playbooks: list[dict[str, Any]], conversation: list[dict[str, str]]) -> str:
        """Generate initial response using MCP tools and playbook information"""
        try:
            # Create enhanced prompt with playbook context
            playbook_context = ""
            if playbooks:
                playbook_context = "\n\n**Relevant Playbooks Found:**\n"
                for i, pb in enumerate(playbooks[:3], 1):  # Show top 3
                    playbook_context += f"{i}. {pb.get('playbook', 'Unknown')}\n"
                    playbook_context += f"   Relevance: {pb.get('relevance_score', 0):.3f}\n"
                    playbook_context += f"   Preview: {pb.get('snippet', 'No preview')[:200]}...\n\n"

            enhanced_prompt = f"""{conversation[-1]['content']}

{playbook_context}

Based on the alert details and available playbooks, provide a comprehensive analysis and recommendations."""

            # Use MCP client to generate response
            response = await self.mcp_client.process_query(
                enhanced_prompt,
                model="claude-3-7-sonnet-20250219",
                max_tokens=2000,
                temperature=0.3
            )

            return response

        except Exception as e:
            logger.error(f"Error generating initial response: {str(e)}")
            return f"Error generating analysis: {str(e)}. Please check the alert details manually."

    async def _generate_final_response(self, conversation: list[dict[str, str]],
                                     playbooks: list[dict[str, Any]]) -> str:
        """Generate final response summary"""
        try:
            # For now, return the last assistant response
            # In a full implementation, this would handle multiple conversation turns
            for message in reversed(conversation):
                if message.get("role") == "assistant":
                    return message.get("content", "No response generated")

            return "No analysis generated"

        except Exception as e:
            logger.error(f"Error generating final response: {str(e)}")
            return "Error generating final response"

    def _extract_search_terms(self, summary: str) -> list[str]:
        """Extract key terms from summary for playbook search"""
        # Simple keyword extraction - in a real implementation, this could be more sophisticated
        key_terms = []

        # Look for common security incident types
        incident_keywords = [
            "brute force", "ssh", "login", "malware", "phishing", "ddos", "data breach",
            "privilege escalation", "lateral movement", "persistence", "exfiltration",
            "credential access", "discovery", "command and control"
        ]

        summary_lower = summary.lower()
        for keyword in incident_keywords:
            if keyword in summary_lower:
                key_terms.append(keyword)

        # If no specific terms found, use general security terms
        if not key_terms:
            key_terms = ["incident response", "security alert"]

        return key_terms[:3]  # Limit to top 3 terms

    def _extract_recommendations(self, response: str) -> list[str]:
        """Extract key recommendations from the LLM response"""
        # Simple extraction - look for numbered or bulleted recommendations
        recommendations = []

        lines = response.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith(('1.', '2.', '3.', '4.', '5.', '•', '-', '*')):
                # Remove the bullet/number prefix
                recommendation = line[2:].strip() if line.startswith(('1.', '2.', '3.', '4.', '5.')) else line[1:].strip()
                if recommendation:
                    recommendations.append(recommendation)

        return recommendations[:10]  # Limit to top 10 recommendations

