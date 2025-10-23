"""
chat_session_manager.py

Manages interactive chat sessions between SOC analysts and the LLM agent.
Handles session creation, state persistence, and conversation flow.
"""

import asyncio
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from src.logger import logger
from src.mcp_client import IntegratedMCPClient
from src.tools.playbook_rag import search_playbooks


class ChatSession:
    """Represents a single chat session between SOC analyst and LLM agent."""

    def __init__(
        self,
        session_id: str,
        alert_summary: str,
        analyst_report: dict,
        mcp_client: IntegratedMCPClient,
        initial_pipeline_data: dict = None,
        alert_id: str = None, alert_data: dict = None,
    ):
        self.session_id = session_id
        self.alert_id = alert_id or "unknown"  # Store the alert ID for reporting
        self.alert_summary = alert_summary  # This is the rule-to-text summary
        self.analyst_report = analyst_report  # This is the analyst ready report
        self.alert_data = alert_data or {}  # Store full alert data for context (not displayed in chat)
        self.mcp_client = mcp_client
        self.initial_pipeline_data = initial_pipeline_data or {}  # Store full pipeline data for completion
        self.created_at = datetime.now()
        self.last_activity = datetime.now()
        self.is_active = True
        self.conversation_history: List[Dict[str, str]] = []
        self.recommended_playbooks: List[Dict[str, Any]] = []

        logger.info(f"ChatSession created - Alert summary length: {len(alert_summary)}")
        logger.info(f"ChatSession created - Analyst report keys: {list(analyst_report.keys())}")
        if alert_summary:
            logger.info(f"ChatSession created - Alert summary preview: {alert_summary[:100]}...")

        # Initialize conversation
        self._initialize_conversation()

    def _initialize_conversation(self):
        """Initialize the conversation with system prompt and initial user message."""
        # Properly format the system prompt with actual alert context
        executive_summary = (
            self.analyst_report.get("executive_summary", "No executive summary available")
            if self.analyst_report
            else "No analyst report available"
        )
        
        # Format alert data as JSON for LLM context (not displayed in chat)
        import json
        alert_data_json = json.dumps(self.alert_data, indent=2) if self.alert_data else "No raw alert data available"

        system_prompt = f"""You are an expert SOC analyst assistant with access to security playbooks and threat intelligence tools.

Your role is to help SOC analysts understand and respond to security alerts by:
1. Analyzing the alert details and providing clear explanations
2. Searching relevant security playbooks using the search_playbook_knowledge or search_security_playbooks_by_topic tools
3. Recommending specific response actions based on best practices from the playbooks
4. Answering follow-up questions and providing additional context

IMPORTANT: When asked about response procedures, incident handling, or playbooks, you MUST use one of these tools:
- search_playbook_knowledge: For specific queries about procedures (e.g., "SSH brute force response steps")
- search_security_playbooks_by_topic: For topic-based searches (e.g., topic="brute force")
- get_available_security_playbooks: To see what playbooks are available

Do not make up procedures - always search the playbook database using the tools.

The conversation should continue until the analyst explicitly ends it.

**Alert Context (for your reference - you can cite specific fields when relevant):**

1. Rule-to-Text Summary (Human-readable):
{self.alert_summary}

2. Analyst Report (Executive Summary):
{executive_summary}

3. Raw Alert Data (Full technical details - reference these when analyst asks for specifics):
```json
{alert_data_json}
```

When the analyst asks about specific alert fields, query parameters, MITRE techniques, or technical details, reference the raw alert data above. The Rule-to-Text Summary is the primary context, but use the raw data for detailed questions."""

        logger.info(f"System prompt created - Length: {len(system_prompt)}")
        logger.info(f"System prompt preview: {system_prompt[:200]}...")
        logger.info(
            f"Alert summary in prompt: {self.alert_summary[:100] if self.alert_summary else 'None'}..."
        )
        logger.info(
            f"Executive summary in prompt: {executive_summary[:100] if executive_summary else 'None'}..."
        )

        self.conversation_history = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": "I need your help analyzing this security alert. Please provide analysis and recommendations based on the rule-to-text summary and analyst report provided in your system context. Use the search_playbook_knowledge or search_security_playbooks_by_topic tools to find relevant response procedures from our security playbooks.",
            },
        ]

    async def add_user_message(self, message: str) -> str:
        """Add a user message and get LLM response."""
        self.last_activity = datetime.now()

        # Add user message to conversation
        self.conversation_history.append({"role": "user", "content": message})

        # Search for relevant playbooks if this seems like a request for procedures
        if any(
            keyword in message.lower() for keyword in ["playbook", "procedure", "response", "action", "step"]
        ):
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
                    "brute force",
                    "ssh",
                    "login",
                    "malware",
                    "phishing",
                    "ddos",
                    "data breach",
                    "privilege escalation",
                    "lateral movement",
                    "persistence",
                    "exfiltration",
                    "credential access",
                    "discovery",
                    "command and control",
                ]

                for keyword in incident_keywords:
                    if keyword in content:
                        key_terms.append(keyword)

        # If no specific terms found, use general security terms
        if not key_terms:
            key_terms = ["incident response", "security alert"]

        return key_terms[:3]  # Limit to top 3 terms

    async def _get_llm_response(self) -> str:
        """Get response from LLM using MCP client with full conversation context."""
        try:
            # Build complete conversation context for the LLM
            conversation_messages = []

            # Always include the system message first (contains alert context)
            for msg in self.conversation_history:
                if msg["role"] == "system":
                    conversation_messages.append({"role": "system", "content": msg["content"]})
                    break

            # Add all conversation history up to the current user message
            # The current user message will be processed by the MCP client
            for msg in self.conversation_history[1:]:  # Skip system message, already added
                conversation_messages.append({"role": msg["role"], "content": msg["content"]})

            # Add playbook context if available and relevant to current conversation
            playbook_context = ""
            if self.recommended_playbooks:
                playbook_context = "\n\n**Available Security Playbooks (from conversation context):**\n"
                for i, pb in enumerate(self.recommended_playbooks[:3], 1):  # Show top 3
                    playbook_context += f"{i}. {pb.get('playbook', 'Unknown')}\n"
                    playbook_context += f"   Relevance Score: {pb.get('relevance_score', 0):.3f}\n"
                    playbook_context += f"   Summary: {pb.get('snippet', 'No preview')[:200]}...\n\n"

            # Add playbook context as an additional system message if available
            if playbook_context:
                playbook_message = (
                    f"Additional Context - Available Security Playbooks:\n"
                    f"{playbook_context}\n"
                    f"Use this context to provide informed recommendations based on "
                    f"the conversation history."
                )
                conversation_messages.append({"role": "system", "content": playbook_message})

            # Debug logging
            logger.info(f"LLM Context - Messages: {len(conversation_messages)}")
            for i, msg in enumerate(conversation_messages[-3:]):  # Show last 3 messages
                msg_idx = len(conversation_messages) - 2 + i
                content_preview = msg["content"][:100] + "..."
                logger.info(f"  Message {msg_idx}: {msg['role']} - {content_preview}")

            # Format the entire conversation context into a single query
            # Include system context, conversation history, and current user message
            full_context = self._build_full_context_query(conversation_messages)

            # Use MCP client to generate response with full context
            response = await self.mcp_client.process_query(
                full_context, model="claude-3-7-sonnet-20250219", max_tokens=2000, temperature=0.3
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

    def _format_conversation_for_query(self, conversation_messages: List[Dict[str, str]]) -> str:
        """Format conversation messages for MCP client query."""
        formatted_parts = []

        for msg in conversation_messages:
            role = msg["role"]
            content = msg["content"]

            if role == "system":
                formatted_parts.append(f"System Context: {content}")
            elif role == "user":
                formatted_parts.append(f"Human: {content}")
            elif role == "assistant":
                formatted_parts.append(f"Assistant: {content}")

        return "\n\n".join(formatted_parts)

    def _build_full_context_query(self, conversation_messages: List[Dict[str, str]]) -> str:
        """Build a complete query string with full conversation context."""
        # Get the current user message (last user message in conversation)
        current_user_msg = None
        for msg in reversed(self.conversation_history):
            if msg["role"] == "user":
                current_user_msg = msg["content"]
                break

        if not current_user_msg:
            current_user_msg = "Please provide analysis and recommendations for this security alert."

        # Format the conversation context
        context_parts = []

        # Add system context
        for msg in conversation_messages:
            if msg["role"] == "system":
                context_parts.append(f"SYSTEM CONTEXT:\n{msg['content']}")
                break

        # Add conversation history
        conversation_text = []
        for msg in conversation_messages:
            if msg["role"] != "system":  # Skip system message, already added
                if msg["role"] == "user":
                    conversation_text.append(f"Human: {msg['content']}")
                elif msg["role"] == "assistant":
                    conversation_text.append(f"Assistant: {msg['content']}")

        if conversation_text:
            context_parts.append(f"CONVERSATION HISTORY:\n{chr(10).join(conversation_text)}")

        # Add current query
        context_parts.append(f"CURRENT QUERY: {current_user_msg}")

        return "\n\n".join(context_parts)

    def get_session_summary(self) -> Dict[str, Any]:
        """Get summary of the chat session for reporting."""
        return {
            "session_id": self.session_id,
            "alert_id": self.alert_id,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_active": self.is_active,
            "message_count": len(self.conversation_history),
            "playbook_count": len(self.recommended_playbooks),
            "alert_summary": (
                self.alert_summary[:200] + "..." if len(self.alert_summary) > 200 else self.alert_summary
            ),
        }

    async def _generate_playbook_recommendation(self) -> str:
        """Generate LLM-based playbook recommendation based on the conversation context."""
        try:
            # Build a summary of the conversation for context
            conversation_summary = []
            for msg in self.conversation_history[-10:]:  # Last 10 messages
                if msg["role"] != "system":
                    role = "Analyst" if msg["role"] == "user" else "Assistant"
                    content = msg["content"][:200] + ("..." if len(msg["content"]) > 200 else "")
                    conversation_summary.append(f"{role}: {content}")
            
            conversation_context = "\n".join(conversation_summary)
            
            # Create prompt for playbook recommendation
            recommendation_prompt = f"""Based on the following security alert analysis conversation, provide a concise recommendation (2-3 paragraphs) on which security playbooks or response procedures should be followed.

**Alert Summary:**
{self.alert_summary[:500]}

**Conversation Context:**
{conversation_context}

Provide specific playbook recommendations that:
1. Match the type of security incident discussed
2. Reference specific playbooks if they were mentioned in the conversation
3. Include the main response steps that should be followed
4. Are actionable for a SOC analyst

Keep it concise and focused on actionable playbook guidance."""

            # Generate recommendation using MCP client
            recommendation = await self.mcp_client.process_query(
                recommendation_prompt,
                model="claude-3-5-haiku-20241022",
                max_tokens=500,
                temperature=0.3
            )
            
            return recommendation.strip()
        
        except Exception as e:
            logger.error(f"Error generating playbook recommendation: {str(e)}")
            return "Unable to generate playbook recommendation at this time."

    async def end_session(self) -> Dict[str, Any]:
        """End the chat session and return final report data."""
        self.is_active = False

        # Extract final recommendations from conversation
        final_recommendations = self._extract_final_recommendations()
        
        # Generate playbook recommendation based on conversation
        playbook_recommendation = await self._generate_playbook_recommendation()

        return {
            "session_id": self.session_id,
            "conversation_history": self.conversation_history,
            "recommended_playbooks": self.recommended_playbooks,
            "final_recommendations": final_recommendations,
            "playbook_recommendation": playbook_recommendation,
            "rule_to_text_summary": self.alert_summary,
            "analyst_ready_report": self.analyst_report,
            "summary": self.get_session_summary(),
        }

    def _extract_final_recommendations(self) -> List[str]:
        """Extract key recommendations from the conversation."""
        recommendations = []

        # Look at assistant responses for actionable recommendations
        for message in self.conversation_history:
            if message["role"] == "assistant":
                content = message["content"]

                # Look for numbered or bulleted items
                lines = content.split("\n")
                for line in lines:
                    line = line.strip()
                    if line.startswith(("1.", "2.", "3.", "4.", "5.", "•", "-", "*")):
                        # Remove the bullet/number prefix
                        if line.startswith(("1.", "2.", "3.", "4.", "5.")):
                            recommendation = line[2:].strip()
                        else:
                            recommendation = line[1:].strip()
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

    async def create_session(
        self,
        alert_summary: str,
        analyst_report: dict,
        initial_pipeline_data: dict = None,
        alert_id: str = None,
        alert_data: dict = None,
    ) -> str:
        """Create a new chat session."""
        session_id = str(uuid.uuid4())

        session = ChatSession(
            session_id, alert_summary, analyst_report, self.mcp_client, initial_pipeline_data, alert_id
        , alert_data)
        self.sessions[session_id] = session

        logger.info(f"Created new chat session: {session_id} for alert: {alert_id}")
        logger.info(f"Total active sessions: {len([s for s in self.sessions.values() if s.is_active])}")
        return session_id

    async def get_session(self, session_id: str) -> Optional[ChatSession]:
        """Get a chat session by ID."""
        logger.info(f"Attempting to get session: {session_id}")
        logger.info(f"Available session IDs: {list(self.sessions.keys())}")

        session = self.sessions.get(session_id)
        if session:
            logger.info(f"Session found: {session_id}, active: {session.is_active}")
            if session.is_active:
                return session
            else:
                logger.warning(f"Session {session_id} is not active")
        else:
            logger.warning(f"Session {session_id} not found in sessions dict")

        return None

    async def send_message(self, session_id: str, message: str) -> Dict[str, Any]:
        """Send a message in a chat session."""
        session = await self.get_session(session_id)
        if not session:
            return {"success": False, "error": "Session not found or inactive"}

        try:
            response = await session.add_user_message(message)

            return {
                "success": True,
                "response": response,
                "recommended_playbooks": session.recommended_playbooks,
            }
        except Exception as e:
            logger.error(f"Error sending message in session {session_id}: {str(e)}")
            return {"success": False, "error": str(e)}

    def _generate_pdf_report(self, session_id: str, report_data: Dict[str, Any]) -> str:
        """Generate a PDF summary report for the chat session.

        Args:
            session_id: The session ID
            report_data: The report data from session.end_session()

        Returns:
            Path to the generated PDF file
        """
        # Create output directory if it doesn't exist
        output_dir = "chat_reports"
        os.makedirs(output_dir, exist_ok=True)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        alert_id = report_data.get("summary", {}).get("alert_id", "unknown")
        filename = f"chat_report_{alert_id}_{timestamp}.pdf"
        filepath = os.path.join(output_dir, filename)

        # Create PDF
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Custom styles
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1a1a1a"),
            spaceAfter=30,
            alignment=1,  # Center
        )

        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=16,
            textColor=colors.HexColor("#2c3e50"),
            spaceAfter=12,
            spaceBefore=12,
        )

        # Title
        story.append(Paragraph("Security Alert Analysis Report", title_style))
        story.append(Spacer(1, 0.3 * inch))

        # Session Info Table
        summary = report_data.get("summary", {})
        session_info = [
            ["Session ID:", session_id[:16] + "..."],
            ["Alert ID:", summary.get("alert_id", "N/A")],
            ["Created:", summary.get("created_at", "N/A")],
            ["Messages:", str(summary.get("message_count", 0))],
            ["Playbooks Used:", str(summary.get("playbook_count", 0))],
        ]

        info_table = Table(session_info, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#ecf0f1")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                    ("PADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        story.append(info_table)
        story.append(Spacer(1, 0.3 * inch))

        # Rule to Text Summary
        story.append(Paragraph("Alert Summary", heading_style))
        alert_summary = report_data.get("rule_to_text_summary", "No summary available")
        # Split into paragraphs for better formatting
        for para in alert_summary.split("\n\n"):
            if para.strip():
                story.append(Paragraph(para.replace("\n", "<br/>"), styles["Normal"]))
                story.append(Spacer(1, 0.1 * inch))
        story.append(Spacer(1, 0.2 * inch))

        # Final Recommendations
        recommendations = report_data.get("final_recommendations", [])
        if recommendations:
            story.append(Paragraph("Key Recommendations", heading_style))
            for i, rec in enumerate(recommendations, 1):
                story.append(Paragraph(f"{i}. {rec}", styles["Normal"]))
                story.append(Spacer(1, 0.1 * inch))
            story.append(Spacer(1, 0.2 * inch))

        # Playbook Recommendations (LLM-generated based on conversation)
        playbook_recommendation = report_data.get("playbook_recommendation", "")
        if playbook_recommendation:
            story.append(Paragraph("Recommended Response Playbooks", heading_style))
            # Split into paragraphs for better formatting
            for para in playbook_recommendation.split('\n\n'):
                if para.strip():
                    story.append(Paragraph(para.replace('\n', '<br/>'), styles["Normal"]))
                    story.append(Spacer(1, 0.1 * inch))
            story.append(Spacer(1, 0.2 * inch))

        # Conversation Highlights (last 5 messages)
        story.append(PageBreak())
        story.append(Paragraph("Conversation Highlights", heading_style))
        conversation = report_data.get("conversation_history", [])

        # Show last 5 exchanges (skip system message)
        messages_to_show = [m for m in conversation if m["role"] != "system"][-10:]

        for msg in messages_to_show:
            role = msg["role"].capitalize()
            content = msg["content"][:500] + ("..." if len(msg["content"]) > 500 else "")

            role_style = ParagraphStyle(
                "Role",
                parent=styles["Normal"],
                fontName="Helvetica-Bold",
                textColor=colors.HexColor("#2980b9") if role == "User" else colors.HexColor("#27ae60"),
                fontSize=11,
            )

            story.append(Paragraph(f"{role}:", role_style))
            story.append(Paragraph(content.replace("\n", "<br/>"), styles["Normal"]))
            story.append(Spacer(1, 0.15 * inch))

        # Footer
        story.append(Spacer(1, 0.5 * inch))
        footer_style = ParagraphStyle(
            "Footer", parent=styles["Normal"], fontSize=8, textColor=colors.grey, alignment=1
        )
        story.append(
            Paragraph(
                f"Generated by TG-Agent Cybersecurity LLM System on "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                footer_style,
            )
        )

        # Build PDF
        doc.build(story)
        logger.info(f"Generated PDF report: {filepath}")
        logger.info(f"📄 PDF Download URL: http://localhost:8001/chat/report/{filename}")

        return filepath

    async def end_session(self, session_id: str) -> Dict[str, Any]:
        """End a chat session and return final report with PDF."""
        logger.info(f"Attempting to end session: {session_id}")
        logger.info(f"Available session IDs: {list(self.sessions.keys())}")

        session = self.sessions.get(session_id)
        if not session:
            logger.error(f"Session {session_id} not found for ending")
            return {"success": False, "error": "Session not found"}

        try:
            logger.info(f"Ending session {session_id}, current status: active={session.is_active}")
            report_data = await session.end_session()
            
            # Generate PDF report
            pdf_path = self._generate_pdf_report(session_id, report_data)

            # Remove from active sessions
            del self.sessions[session_id]

            logger.info(f"Successfully ended chat session: {session_id}")

            return {
                "success": True,
                "report": report_data,
                "recommendations_count": len(report_data["final_recommendations"]),
                "pdf_report": pdf_path,
                "pdf_filename": os.path.basename(pdf_path),
            }
        except Exception as e:
            logger.error(f"Error ending session {session_id}: {str(e)}")
            return {"success": False, "error": str(e)}

    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get list of active session summaries."""
        return [session.get_session_summary() for session in self.sessions.values() if session.is_active]

    def get_session_count(self) -> int:
        """Get total number of active sessions."""
        return len([s for s in self.sessions.values() if s.is_active])
