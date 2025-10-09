"""
chat_session_manager.py

Manages interactive chat sessions between SOC analysts and the LLM agent.
Handles session creation, state persistence, and conversation flow.
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.tools.playbook_rag import search_playbooks


class ChatSession:
    """Represents a single chat session between SOC analyst and LLM agent."""

    def __init__(self, session_id: str, alert_summary: str, analyst_report: dict, mcp_client: IntegratedMCPClient):
        self.session_id = session_id
        self.alert_summary = alert_summary
        self.analyst_report = analyst_report
        self.mcp_client = mcp_client
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True
        self.conversation_history: List[Dict[str, str]] = []
        self.recommended_playbooks: List[Dict[str, Any]] = []

        # Initialize conversation
        self._initialize_conversation()

    def _initialize_conversation(self):
        """Initialize the conversation with system prompt and initial user message."""
        system_prompt = """You are an expert SOC analyst assistant with access to security playbooks and threat intelligence tools.

Your role is to help SOC analysts understand and respond to security alerts by:
1. Analyzing the alert details and providing clear explanations
2. Searching relevant security playbooks using available tools
3. Recommending specific response actions based on best practices
4. Answering follow-up questions and providing additional context

Always use the playbook_rag tool when recommending response procedures to ensure accuracy and completeness.

The conversation should continue until the analyst explicitly ends it."""

        initial_user_message = f"""I need your help analyzing this security alert:

**Alert Summary:**
{self.alert_summary}

**Analyst Report:**
{self.analyst_report.get('executive_summary', 'No executive summary available')}

Please provide:
1. A clear explanation of what this alert means
2. Recommended response procedures from relevant playbooks
3. Any immediate actions that should be taken
4. Additional investigation steps if needed

Use the available tools to search for relevant security playbooks."""

        self.conversation_history = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": initial_user_message}
        ]

    async def add_user_message(self, message: str) -> str:
        """Add a user message and get LLM response."""
        self.last_activity = datetime.now()

        # Add user message to conversation
        self.conversation_history.append({"role": "user", "content": message})

        # Search for relevant playbooks if this seems like a request for procedures
        if any(keyword in message.lower() for keyword in ["playbook", "procedure", "response", "action", "step"]):
            await self._update_playbook_recommendations()

        # Get LLM response
        response = await self._get_llm_response()

        # Add assistant response to conversation
        self.conversation_history.append({"role": "assistant", "content": response})

        return response

    async def _update_playbook_recommendations(self):
        """Update playbook recommendations based on current conversation."""
        try:
            # Extract key terms from the latest messages
            search_terms = self._extract_search_terms()

            # Search for relevant playbooks
            search_results = []
            for term in search_terms:
                results = search_playbooks(f"security incident response playbook for {term}", top_k=3)
                if results.get("success", False):
                    search_results.extend(results.get("results", []))

            # Remove duplicates and update recommendations
            unique_playbooks = {}
            for result in search_results:
                playbook_name = result.get("playbook", "")
                if playbook_name not in unique_playbooks:
                    unique_playbooks[playbook_name] = result

            self.recommended_playbooks = list(unique_playbooks.values())

        except Exception as e:
            logger.error(f"Error updating playbook recommendations: {str(e)}")

    def _extract_search_terms(self) -> List[str]:
        """Extract key terms from conversation for playbook search."""
        # Look at recent messages for security-related terms
        recent_messages = self.conversation_history[-3:]  # Last 3 messages

        key_terms = []
        for message in recent_messages:
            if message["role"] == "user":
                content = message["content"].lower()

                # Look for common security incident types
                incident_keywords = [
                    "brute force", "ssh", "login", "malware", "phishing", "ddos", "data breach",
                    "privilege escalation", "lateral movement", "persistence", "exfiltration",
                    "credential access", "discovery", "command and control"
                ]

                for keyword in incident_keywords:
                    if keyword in content:
                        key_terms.append(keyword)

        # If no specific terms found, use general security terms
        if not key_terms:
            key_terms = ["incident response", "security alert"]

        return key_terms[:3]  # Limit to top 3 terms

    async def _get_llm_response(self) -> str:
        """Get response from LLM using MCP client."""
        try:
            # Create enhanced prompt with current conversation context
            conversation_text = self._format_conversation_for_llm()

            # Add playbook context if available
            playbook_context = ""
            if self.recommended_playbooks:
                playbook_context = "\n\n**Relevant Playbooks Found:**\n"
                for i, pb in enumerate(self.recommended_playbooks[:3], 1):  # Show top 3
                    playbook_context += f"{i}. {pb.get('playbook', 'Unknown')}\n"
                    playbook_context += f"   Relevance: {pb.get('relevance_score', 0):.3f}\n"
                    playbook_context += f"   Preview: {pb.get('snippet', 'No preview')[:200]}...\n\n"

            full_prompt = f"{conversation_text}\n\n{playbook_context}\n\nProvide a comprehensive response based on the conversation context."

            # Use MCP client to generate response
            response = await self.mcp_client.process_query(
                full_prompt,
                model="claude-3-7-sonnet-20250219",
                max_tokens=2000,
                temperature=0.3
            )

            return response

        except Exception as e:
            logger.error(f"Error getting LLM response: {str(e)}")
            return f"Error generating response: {str(e)}. Please check your query and try again."

    def _format_conversation_for_llm(self) -> str:
        """Format conversation history for LLM input."""
        formatted_messages = []
        for message in self.conversation_history[-5:]:  # Last 5 messages for context
            role = message["role"]
            content = message["content"]

            if role == "system":
                formatted_messages.append(f"System: {content}")
            elif role == "user":
                formatted_messages.append(f"Human: {content}")
            elif role == "assistant":
                formatted_messages.append(f"Assistant: {content}")

        return "\n\n".join(formatted_messages)

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of the chat session for reporting."""
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_active": self.is_active,
            "message_count": len(self.conversation_history),
            "playbook_count": len(self.recommended_playbooks),
            "alert_summary": self.alert_summary[:200] + "..." if len(self.alert_summary) > 200 else self.alert_summary
        }

    def end_session(self) -> Dict[str, Any]:
        """End the chat session and return final report data."""
        self.is_active = False

        # Extract final recommendations from conversation
        final_recommendations = self._extract_final_recommendations()

        return {
            "session_id": self.session_id,
            "conversation_history": self.conversation_history,
            "recommended_playbooks": self.recommended_playbooks,
            "final_recommendations": final_recommendations,
            "summary": self.get_session_summary()
        }

    def _extract_final_recommendations(self) -> List[str]:
        """Extract key recommendations from the conversation."""
        recommendations = []

        # Look at assistant responses for actionable recommendations
        for message in self.conversation_history:
            if message["role"] == "assistant":
                content = message["content"]

                # Look for numbered or bulleted items
                lines = content.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith(('1.', '2.', '3.', '4.', '5.', '•', '-', '*')):
                        # Remove the bullet/number prefix
                        recommendation = line[2:].strip() if line.startswith(('1.', '2.', '3.', '4.', '5.')) else line[1:].strip()
                        if recommendation and len(recommendation) > 10:  # Filter out short items
                            recommendations.append(recommendation)

        return recommendations[:10]  # Limit to top 10 recommendations


class ChatSessionManager:
    """Manages multiple chat sessions."""

    def __init__(self, mcp_client: IntegratedMCPClient):
        self.mcp_client = mcp_client
        self.sessions: Dict[str, ChatSession] = {}
        self._cleanup_task = None

        # Start cleanup task for inactive sessions
        self._start_cleanup_task()

    def _start_cleanup_task(self):
        """Start background task to clean up inactive sessions."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_inactive_sessions())

    async def _cleanup_inactive_sessions(self):
        """Clean up sessions that have been inactive for too long."""
        while True:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes

                current_time = datetime.now()
                inactive_threshold = timedelta(hours=2)  # 2 hours of inactivity

                sessions_to_remove = []
                for session_id, session in self.sessions.items():
                    if (current_time - session.last_activity) > inactive_threshold:
                        sessions_to_remove.append(session_id)
                        logger.info(f"Cleaning up inactive chat session: {session_id}")

                for session_id in sessions_to_remove:
                    del self.sessions[session_id]

            except Exception as e:
                logger.error(f"Error in session cleanup: {str(e)}")

    async def create_session(self, alert_summary: str, analyst_report: dict) -> str:
        """Create a new chat session."""
        session_id = str(uuid.uuid4())

        session = ChatSession(session_id, alert_summary, analyst_report, self.mcp_client)
        self.sessions[session_id] = session

        logger.info(f"Created new chat session: {session_id}")
        return session_id

    async def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Get a chat session by ID."""
        session = self.sessions.get(session_id)
        if session and session.is_active:
            return session
        return None

    async def send_message(self, session_id: str, message: str) -> Dict[str, Any]:
        """Send a message in a chat session."""
        session = await self.get_session(session_id)
        if not session:
            return {
                "success": False,
                "error": "Session not found or inactive"
            }

        try:
            response = await session.add_user_message(message)

            return {
                "success": True,
                "response": response,
                "recommended_playbooks": session.recommended_playbooks
            }
        except Exception as e:
            logger.error(f"Error sending message in session {session_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def end_session(self, session_id: str) -> Dict[str, Any]:
        """End a chat session and return final report."""
        session = self.sessions.get(session_id)
        if not session:
            return {
                "success": False,
                "error": "Session not found"
            }

        try:
            report_data = session.end_session()

            # Remove from active sessions
            del self.sessions[session_id]

            logger.info(f"Ended chat session: {session_id}")

            return {
                "success": True,
                "report": report_data,
                "recommendations_count": len(report_data["final_recommendations"])
            }
        except Exception as e:
            logger.error(f"Error ending session {session_id}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active session summaries."""
        return [session.get_session_summary() for session in self.sessions.values() if session.is_active]

    def get_session_count(self) -> int:
        """Get total number of active sessions."""
        return len([s for s in self.sessions.values() if s.is_active])
