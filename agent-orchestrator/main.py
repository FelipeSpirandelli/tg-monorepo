import json
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from src.agent_manager import AgentManager
from src.chat_session_manager import ChatSessionManager
from src.logger import logger
from src.models import AgentResponse, AlertRequest, ElasticAlertData


# Define lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting FastAPI application...")
    logger.info("Initializing MVC agent...")
    try:
        await agent_manager.initialize_mvc_agent()
        # Initialize chat session manager after agent manager
        global chat_session_manager
        chat_session_manager = ChatSessionManager(agent_manager.mcp_client)
        logger.info("Chat session manager initialized successfully")
        logger.info("MVC agent initialized successfully during startup")
    except Exception as e:
        logger.error(f"Failed to initialize MVC agent during startup: {str(e)}")
        raise
    yield
    if agent_manager.mcp_client:
        await agent_manager.mcp_client.cleanup()
        logger.info("Integrated MCP client cleanup completed")
    logger.info("FastAPI application shutdown complete")


# Initialize the agent manager and chat session manager
agent_manager = AgentManager()
chat_session_manager = None


async def process_alert_interactive_mode(alert_data: dict, alert_id: str) -> dict:
    """Process alert in interactive mode - initial pipeline + chat session creation"""
    try:
        # Process through initial pipeline steps (up to translation engine)
        initial_pipeline = [
            "alert_processing",
            "ioc_extractor",
            "translation_engine"
        ]

        logger.info(f"Processing alert {alert_id} in interactive mode - initial pipeline")
        initial_result = await agent_manager.pipeline_processor.process(alert_data, initial_pipeline)

        # Extract the natural language summary and analyst report
        natural_language_summary = initial_result.get("natural_language_summary", "")
        analyst_ready_report = initial_result.get("analyst_ready_report", {})

        logger.info(f"Alert processing - Natural language summary length: {len(natural_language_summary)}")
        logger.info(f"Alert processing - Analyst report keys: {list(analyst_ready_report.keys())}")

        if natural_language_summary:
            logger.info(f"Alert processing - Summary preview: {natural_language_summary[:200]}...")
        else:
            logger.warning("Alert processing - No natural language summary generated!")

        if not natural_language_summary:
            raise ValueError("No natural language summary generated from initial pipeline")

        # Create a chat session for interactive analysis with actual rule-to-text context
        if chat_session_manager is None:
            raise ValueError("Chat session manager not initialized")

        logger.info(f"Creating chat session with alert summary length: {len(natural_language_summary)}")
        logger.info(f"Chat manager instance ID before create: {id(chat_session_manager)}")
        
        # Pass the full initial_result to the session for later use in completion
        session_id = await chat_session_manager.create_session(natural_language_summary, analyst_ready_report, initial_result, alert_id)

        # Get the session to extract data for the response
        session = await chat_session_manager.get_session(session_id)
        if not session:
            raise ValueError("Failed to retrieve created chat session")
        
        logger.info(f"Session {session_id} created and verified in manager {id(chat_session_manager)}")

        logger.info(f"Created interactive chat session {session_id} for alert {alert_id}")

        return {
            "mode": "interactive",
            "alert_id": alert_id,
            "session_id": session_id,
            "status": "chat_session_created",
            "alert_summary": natural_language_summary,
            "analyst_report": analyst_ready_report,
            "recommended_playbooks": session.recommended_playbooks,
            "message": "Interactive chat session created. Use /chat/message to interact with the agent."
        }

    except Exception as e:
        logger.error(f"Error in interactive alert processing: {str(e)}")
        raise


async def save_complete_results_to_file(result: dict, alert_id: str) -> None:
    """Save complete pipeline results to JSON file for analysis"""
    try:
        # Create output directory if it doesn't exist
        output_dir = "llm_analysis_outputs"
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Create filename with timestamp and alert ID
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{output_dir}/alert_analysis_{alert_id}_{timestamp}.json"
        
        # Prepare comprehensive analysis data
        analysis_data = {
            "metadata": {
                "alert_id": alert_id,
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "complete_llm_pipeline"
            },
            "pipeline_results": result,
            "llm_outputs": {
                "initial_summary": result.get("natural_language_summary"),
                "final_mcp_response": result.get("mcp_response"),
                "formatted_response": result.get("formatted_response")
            },
            "extracted_intelligence": {
                "iocs": result.get("extracted_iocs", {}),
                "alert_details": result.get("processed_alert", {}),
                "analyst_report": result.get("analyst_ready_report", {})
            }
        }
        
        # Save to file with pretty formatting
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Complete LLM analysis saved to: {filename}")
        print(f"📁 Complete LLM analysis saved to: {filename}")
        
    except Exception as e:
        logger.error(f"Error saving analysis to file: {str(e)}")
        print(f"❌ Error saving analysis: {str(e)}")


# Pass the lifespan to the FastAPI app
app = FastAPI(title="Agent Orchestrator", lifespan=lifespan)

# Alert completion endpoint for interactive sessions
@app.post("/alert/complete")
async def complete_interactive_alert(request: Request):
    """Complete an interactive alert session and generate final report"""
    try:
        data = await request.json()
        session_id = data.get("session_id")
        alert_id = data.get("alert_id")

        logger.info(f"Alert completion request: session_id={session_id}, alert_id={alert_id}")
        logger.info(f"Chat manager instance ID at completion: {id(chat_session_manager) if chat_session_manager else 'None'}")
        logger.info(f"Available sessions in manager: {list(chat_session_manager.sessions.keys()) if chat_session_manager else 'No manager'}")

        if not session_id or not alert_id:
            raise HTTPException(status_code=400, detail="session_id and alert_id are required")

        if chat_session_manager is None:
            raise HTTPException(status_code=500, detail="Chat session manager not initialized")

        # Get the session BEFORE ending it to access initial pipeline data
        session = await chat_session_manager.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        # Get the initial pipeline data stored in the session
        initial_pipeline_data = session.initial_pipeline_data
        
        # End the chat session and get the report
        chat_result = await chat_session_manager.end_session(session_id)

        if not chat_result.get("success", False):
            logger.error(f"Failed to end chat session: {chat_result.get('error')}")
            raise HTTPException(status_code=400, detail=f"Failed to end chat session: {chat_result.get('error')}")

        report = chat_result.get("report", {})

        # Get the original alert context from the chat session
        natural_language_summary = report.get("rule_to_text_summary", "")
        analyst_ready_report = report.get("analyst_ready_report", {})
        conversation_history = report.get("conversation_history", [])
        recommended_playbooks = report.get("recommended_playbooks", [])
        final_recommendations = report.get("final_recommendations", [])

        logger.info(f"Retrieved chat report - Summary length: {len(natural_language_summary)}, Recommendations: {len(final_recommendations)}")

        # Create pipeline data with all the context from the chat session
        # This includes the original alert context plus the chat insights AND the initial pipeline data
        pipeline_data = {
            **initial_pipeline_data,  # Include all data from initial pipeline (includes processed_alert, etc.)
            "natural_language_summary": natural_language_summary,
            "analyst_ready_report": analyst_ready_report,
            "conversation_history": conversation_history,
            "recommended_playbooks": recommended_playbooks,
            "chat_insights": {
                "final_recommendations": final_recommendations,
                "message_count": len(conversation_history),
                "playbook_count": len(recommended_playbooks)
            }
        }

        # Process through final pipeline steps
        final_pipeline = [
            "prompt_generation",
            "mcp_query",
            "response_formatting"
        ]

        logger.info(f"Completing interactive alert {alert_id} - running final pipeline steps")
        final_result = await agent_manager.pipeline_processor.process(pipeline_data, final_pipeline)

        # Merge chat results with final pipeline results
        complete_result = {
            "alert_id": alert_id,
            "mode": "interactive_completed",
            "rule_to_text_summary": natural_language_summary,
            "analyst_ready_report": analyst_ready_report,
            "chat_session": report,
            "final_analysis": final_result,
            "pdf_report": chat_result.get("pdf_report"),
            "pdf_filename": chat_result.get("pdf_filename"),
            "pdf_download_url": f"http://localhost:8001/chat/report/{chat_result.get('pdf_filename')}" if chat_result.get("pdf_filename") else None,
            "summary": {
                "alert_id": alert_id,
                "chat_messages": len(report.get("conversation_history", [])),
                "playbooks_found": len(report.get("recommended_playbooks", [])),
                "recommendations": len(report.get("final_recommendations", [])),
                "completed_at": datetime.now().isoformat()
            }
        }

        # Save complete results to file
        await save_complete_results_to_file(complete_result, alert_id)
        
        # Log the PDF download link
        if complete_result.get("pdf_download_url"):
            logger.info(f"📄 Chat Session PDF Report: {complete_result['pdf_download_url']}")

        return AgentResponse(response=complete_result)

    except Exception as e:
        logger.error(f"Error completing interactive alert: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error completing alert: {str(e)}") from e

# Mount static files (for CSS, JS, etc. if needed)
# app.mount("/static", StaticFiles(directory="static"), name="static")

# Serve chat interface HTML
@app.get("/chat_interface.html", response_class=HTMLResponse)
async def get_chat_interface():
    """Serve the SOC analyst chat interface"""
    chat_file = os.path.join(os.path.dirname(__file__), "chat_interface.html")
    if os.path.exists(chat_file):
        with open(chat_file, 'r', encoding='utf-8') as f:
            return f.read()
    else:
        raise HTTPException(status_code=404, detail="Chat interface not found")


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "agent-orchestrator"}


@app.post("/alert", response_model=AgentResponse)
async def process_alert(request: Request):
    """
    Process an incoming alert through the default pipeline
    Handles both JSON and form-urlencoded data from Elastic Security
    """
    try:
        content_type = request.headers.get("content-type", "")

        if "application/x-www-form-urlencoded" in content_type:
            # Handle form-encoded data from Elastic
            form = await request.form()
            form_data = {}

            # Convert form data to the expected format
            for key, value in form.items():
                form_data[key] = [str(value)]

            # Create ElasticAlertData with form_data
            elastic_data = ElasticAlertData(
                timestamp="2025-09-21T20:09:20.677361",
                method=request.method,
                headers=dict(request.headers),
                url=str(request.url),
                remote_addr=request.client.host if request.client else "unknown",
                user_agent=request.headers.get("user-agent", "unknown"),
                form_data=form_data,
            )

            logger.info(f"Processed form data with keys: {list(form_data.keys())}")

        elif "application/json" in content_type:
            # Handle direct JSON data (legacy or testing)
            json_data = await request.json()

            if "alert_data" in json_data:
                # Direct AlertRequest format
                alert_request = AlertRequest.model_validate(json_data)
                elastic_data = alert_request.alert_data
            else:
                # Assume it's ElasticAlertData format
                elastic_data = ElasticAlertData.model_validate(json_data)

            logger.info("Processed JSON data")

        else:
            raise ValueError(f"Unsupported content type: {content_type}")

        # Prepare the initial data with the alert
        initial_data = {"alert_data": elastic_data.model_dump()}

        # Ensure agent manager is initialized before processing
        if agent_manager.mcp_client is None:
            logger.info("Agent manager not initialized, initializing now...")
            await agent_manager.initialize_mvc_agent()

        # Process alert in interactive mode (default behavior)
        initial_result = await process_alert_interactive_mode(initial_data, elastic_data.alert.id)

        # Add chat interface URL to the response
        chat_url = f"http://localhost:8001/chat_interface.html?alert_id={elastic_data.alert.id}&session_id={initial_result['session_id']}"
        initial_result["chat_interface_url"] = chat_url
        initial_result["instructions"] = f"🔗 CHAT INTERFACE: {chat_url}\n\nOpen this URL in your browser to start the interactive chat session for this alert."

        # Log the chat interface URL prominently
        logger.info(f"🔗 CHAT INTERFACE URL: {chat_url}")
        logger.info(f"📋 Alert ID: {elastic_data.alert.id}")
        logger.info(f"🔑 Session ID: {initial_result['session_id']}")
        print(f"\n🔗 CHAT INTERFACE: {chat_url}")
        print(f"📋 Alert ID: {elastic_data.alert.id}")
        print(f"🔑 Session ID: {initial_result['session_id']}\n")

        return AgentResponse(response=initial_result)

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}") from e




# Chat endpoints for interactive SOC analyst interface
@app.post("/chat/init")
async def initialize_chat(request: Request):
    """Initialize a new chat session for SOC analyst interaction."""
    try:
        data = await request.json()
        alert_id = data.get("alert_id")
        session_id_param = data.get("session_id")

        logger.info(f"Chat init request: alert_id={alert_id}, session_id={session_id_param}")

        if chat_session_manager is None:
            raise HTTPException(status_code=500, detail="Chat session manager not initialized")

        # If session_id is provided, try to connect to existing session
        if session_id_param:
            logger.info(f"Attempting to connect to existing session: {session_id_param}")
            existing_session = await chat_session_manager.get_session(session_id_param)

            if existing_session:
                logger.info(f"✅ Connected to existing session: {session_id_param}")
                return {
                    "success": True,
                    "session_id": session_id_param,
                    "alert_id": existing_session.alert_summary[:50] + "..." if existing_session.alert_summary else alert_id,
                    "alert_summary": existing_session.alert_summary,
                    "recommended_playbooks": existing_session.recommended_playbooks,
                    "existing_conversation": existing_session.conversation_history
                }
            else:
                logger.warning(f"Session {session_id_param} not found, creating new session")
                # Fall through to create new session

        # Create a new session
        logger.info("Creating new chat session")
        if alert_id:
            # For existing alerts, use a more generic summary since we don't have the actual rule-to-text
            alert_summary = f"Security alert {alert_id} detected. Please analyze and provide response recommendations."
        else:
            alert_summary = "Security alert detected. Please analyze and provide response recommendations."

        analyst_report = {
            "executive_summary": "Initial alert analysis session started."
        }

        session_id = await chat_session_manager.create_session(alert_summary, analyst_report)

        # Get the session to extract initial data
        session = await chat_session_manager.get_session(session_id)
        if not session:
            raise HTTPException(status_code=500, detail="Failed to retrieve created session")

        logger.info(f"✅ Created new chat session: {session_id}")

        return {
            "success": True,
            "session_id": session_id,
            "alert_id": alert_id or "new_session",
            "alert_summary": session.alert_summary,
            "recommended_playbooks": session.recommended_playbooks,
            "existing_conversation": session.conversation_history
        }

    except Exception as e:
        logger.error(f"Error initializing chat: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error initializing chat: {str(e)}") from e


@app.post("/chat/message")
async def send_chat_message(request: Request):
    """Send a message in an existing chat session."""
    try:
        data = await request.json()
        session_id = data.get("session_id")
        message = data.get("message")

        if not session_id or not message:
            raise HTTPException(status_code=400, detail="session_id and message are required")

        if chat_session_manager is None:
            raise HTTPException(status_code=500, detail="Chat session manager not initialized")

        result = await chat_session_manager.send_message(session_id, message)

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:
        logger.error(f"Error sending chat message: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error sending message: {str(e)}") from e


@app.post("/chat/end")
async def end_chat_session(request: Request):
    """End a chat session and generate final report."""
    try:
        data = await request.json()
        session_id = data.get("session_id")

        if not session_id:
            raise HTTPException(status_code=400, detail="session_id is required")

        if chat_session_manager is None:
            raise HTTPException(status_code=500, detail="Chat session manager not initialized")

        result = await chat_session_manager.end_session(session_id)

        if not result["success"]:
            raise HTTPException(status_code=400, detail=result["error"])

        return result

    except Exception as e:
        logger.error(f"Error ending chat session: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error ending chat: {str(e)}") from e


@app.get("/chat/sessions")
async def get_active_sessions():
    """Get list of active chat sessions."""
    try:
        if chat_session_manager is None:
            raise HTTPException(status_code=500, detail="Chat session manager not initialized")

        sessions = chat_session_manager.get_active_sessions()
        return {
            "success": True,
            "active_sessions": sessions,
            "total_count": chat_session_manager.get_session_count()
        }

    except Exception as e:
        logger.error(f"Error getting active sessions: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error getting sessions: {str(e)}") from e


@app.get("/chat/report/{filename}")
async def download_chat_report(filename: str):
    """Download a PDF report from a completed chat session."""
    try:
        # Validate filename to prevent directory traversal
        if ".." in filename or "/" in filename or "\\" in filename:
            raise HTTPException(status_code=400, detail="Invalid filename")
        
        # Check if file exists
        report_path = os.path.join("chat_reports", filename)
        if not os.path.exists(report_path):
            raise HTTPException(status_code=404, detail="Report not found")
        
        logger.info(f"Serving PDF report: {filename}")
        
        return FileResponse(
            path=report_path,
            media_type="application/pdf",
            filename=filename,
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving PDF report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error serving report: {str(e)}") from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
