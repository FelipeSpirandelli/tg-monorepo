import json
import os
import re
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from src.agent_manager import AgentManager
from src.chat_session_manager import ChatSessionManager
from src.logger import logger
from src.models import AgentResponse, AlertRequest, ElasticAlertData


def parse_malformed_elastic_alert(data: dict) -> dict:
    """
    Parse malformed Elastic alerts where form-data was incorrectly converted to JSON strings.
    
    This handles cases where alert_data contains keys that are giant JSON strings
    instead of proper objects.
    
    Example input:
    {
        "alert_data": {
            "{\\n    \"alert\": \"{...}\",\\n    \"rule\": \"{...}\"": [""],
            "...more escaped JSON...": [""]
        }
    }
    """
    if "alert_data" not in data:
        return data
    
    alert_data = data["alert_data"]
    
    # Check if this is the malformed format (dict with string keys containing JSON)
    if not isinstance(alert_data, dict):
        return data
    
    # Look for keys that contain JSON-like content
    # Also check values - sometimes the JSON is split across keys AND values
    combined_json_str = ""
    for key, value in alert_data.items():
        if isinstance(key, str) and ("{" in key or "\"" in key):
            # This key contains JSON content
            combined_json_str += key
        # Also check if values contain JSON strings (for context, alert, etc.)
        if isinstance(value, list) and len(value) > 0:
            for val in value:
                if isinstance(val, str) and ("{" in val or "\"" in val):
                    combined_json_str += val
    
    if not combined_json_str:
        return data
    
    logger.info("Detected malformed form-data alert format, attempting to parse...")
    
    try:
        # Try to extract JSON objects from the combined string
        # Look for the main components: alert, rule, context
        result = {}
        
        # Extract alert JSON - it's double-escaped in the malformed format
        # Format: "alert": "{\"id\":\"...\",\"uuid\":\"...\"}"
        alert_match = re.search(r'"alert":\s*"(\{\\?"[^}]*\})"', combined_json_str)
        if alert_match:
            alert_str = alert_match.group(1)
            # Remove escape characters
            alert_str = alert_str.replace('\\"', '"').replace('\\n', '').replace('\\', '')
            try:
                result["alert"] = json.loads(alert_str)
                logger.info(f"Extracted alert: {result['alert'].get('id', 'unknown')}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse alert JSON: {e}, raw: {alert_str[:100]}")
                # Create a minimal alert if extraction fails
                result["alert"] = {
                    "id": "unknown-malformed-alert",
                    "uuid": "unknown-malformed-alert",
                    "actionGroup": "default",
                    "actionGroupName": "Default",
                    "flapping": False
                }
                logger.info("Created fallback alert")
        else:
            # No alert found, create fallback
            logger.warning("No alert found in malformed data, creating fallback")
            result["alert"] = {
                "id": "unknown-malformed-alert",
                "uuid": "unknown-malformed-alert",
                "actionGroup": "default",
                "actionGroupName": "Default",
                "flapping": False
            }
        
        # Extract rule JSON (may be split across multiple parts)
        rule_match = re.search(r'"rule":\s*"(\{.*)', combined_json_str, re.DOTALL)
        if rule_match:
            # The rule JSON is massive and may be cut off, try to find the complete JSON
            rule_start = combined_json_str.find('"rule":')
            if rule_start != -1:
                # Find the next key or end
                context_start = combined_json_str.find('"context":', rule_start)
                if context_start != -1:
                    rule_section = combined_json_str[rule_start:context_start]
                else:
                    rule_section = combined_json_str[rule_start:]
                
                # Extract the JSON value
                rule_value_match = re.search(r'"rule":\s*"(\{.*?(?:\}(?![^{]*\{)|\}$))', rule_section, re.DOTALL)
                if rule_value_match:
                    rule_str = rule_value_match.group(1).replace('\\"', '"')
                    # Try to parse what we have
                    try:
                        result["rule"] = json.loads(rule_str)
                    except json.JSONDecodeError:
                        # Try to extract key fields from the malformed rule string
                        logger.warning("Rule JSON incomplete, attempting to extract key fields...")
                        
                        # Extract specific fields we need for IoC extraction
                        rule_name = "Potential Linux Local Account Brute Force Detected"
                        name_match = re.search(r'"name":\s*"([^"]+)"', combined_json_str)
                        if name_match:
                            rule_name = name_match.group(1)
                        
                        # Try to extract description (contains important context)
                        description = "Identifies multiple consecutive login attempts"
                        desc_match = re.search(r'"description":\s*"([^"]+(?:\\.[^"]*)*)"', combined_json_str)
                        if desc_match:
                            description = desc_match.group(1).replace('\\"', '"')[:500]  # First 500 chars
                        
                        # Try to extract query (contains IoCs!) - let LLM extract IoCs, not regex
                        query = ""
                        query_match = re.search(r'"query":\s*"([^"]+(?:\\.[^"]*)*)"', combined_json_str)
                        if query_match:
                            query = query_match.group(1).replace('\\"', '"').replace('\\n', '\n')
                            logger.info(f"Extracted query field: {query[:100]}...")
                        
                        # Try to extract severity
                        severity = "medium"
                        sev_match = re.search(r'"severity":\s*"([^"]+)"', combined_json_str)
                        if sev_match:
                            severity = sev_match.group(1)
                        
                        # Create a minimal rule object with extracted data
                        result["rule"] = {
                            "id": "malformed-extracted",
                            "name": rule_name,
                            "type": "eql",
                            "spaceId": "default",
                            "tags": ["malformed-alert-partial-extraction"],
                            "params": {
                                "description": description,
                                "severity": severity,
                                "riskScore": 47,
                                "query": query,  # This is critical for IoC extraction!
                                "language": "eql",
                            }
                        }
                    logger.info(f"Extracted rule: {result['rule'].get('name', 'unknown')}")
        
        # Extract context JSON (may contain actual alert event data with IoCs!)
        # Context is usually a large nested structure with the actual alert events
        context_start = combined_json_str.find('"context":')
        if context_start != -1:
            logger.info("Found context section, attempting to extract...")
            
            # Find the start of the context value (after "context":)
            context_value_start = combined_json_str.find(':', context_start) + 1
            
            # Skip whitespace
            while context_value_start < len(combined_json_str) and combined_json_str[context_value_start] in ' \t\n':
                context_value_start += 1
            
            # Check if it starts with a quote (escaped JSON string)
            if context_value_start < len(combined_json_str) and combined_json_str[context_value_start] == '"':
                # Extract the entire escaped JSON string value
                # Start after the opening quote
                start_pos = context_value_start + 1
                end_pos = start_pos
                depth = 0
                in_string = False
                escape_next = False
                
                # Find the matching closing quote, accounting for escaped quotes
                while end_pos < len(combined_json_str):
                    char = combined_json_str[end_pos]
                    
                    if escape_next:
                        escape_next = False
                        end_pos += 1
                        continue
                    
                    if char == '\\':
                        escape_next = True
                        end_pos += 1
                        continue
                    
                    if char == '"' and not escape_next:
                        # Check if this is the closing quote (not inside braces)
                        # Simple check: if we're not inside any braces, this is likely the end
                        if depth == 0:
                            # Double-check: look ahead to see if there's a comma or closing brace
                            next_char_pos = end_pos + 1
                            while next_char_pos < len(combined_json_str) and combined_json_str[next_char_pos] in ' \t\n':
                                next_char_pos += 1
                            if next_char_pos >= len(combined_json_str) or combined_json_str[next_char_pos] in ',}':
                                break
                    
                    if char == '{':
                        depth += 1
                    elif char == '}':
                        depth -= 1
                    
                    end_pos += 1
                
                # Extract the context string
                context_str_escaped = combined_json_str[start_pos:end_pos]
                
                # Unescape the JSON string
                # Replace escaped quotes and newlines
                context_str = context_str_escaped.replace('\\"', '"').replace('\\n', '\n').replace('\\\\', '\\')
                
                # Remove control characters that break JSON parsing
                import string
                context_str = ''.join(char for char in context_str if char in string.printable or char in '\n\r\t')
                
                # Try to parse the JSON
                try:
                    result["context"] = json.loads(context_str)
                    logger.info(f"Successfully extracted and parsed context JSON")
                    # Check if context has alerts array
                    if isinstance(result["context"], dict) and "alerts" in result["context"]:
                        logger.info(f"Found {len(result['context']['alerts'])} alerts in context")
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse context JSON: {e}")
                    logger.warning(f"Context string preview (first 500 chars): {context_str[:500]}")
                    
                    # Try to extract IoCs directly from the context string using multiple methods
                    # Method 1: Extract from reason field (e.g., "source 186.194.168.172 by testuser")
                    reason_ip_pattern = r'source\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
                    reason_user_pattern = r'by\s+(\w+)\s+on'
                    reason_process_pattern = r'process\s+(\w+)'
                    
                    ip_matches = re.findall(reason_ip_pattern, context_str)
                    user_matches = re.findall(reason_user_pattern, context_str)
                    process_matches = re.findall(reason_process_pattern, context_str)
                    
                    # Method 2: Extract from JSON structure patterns
                    if not ip_matches:
                        ip_matches = re.findall(r'"source"[^}]*"ip"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"', context_str)
                    if not user_matches:
                        user_matches = re.findall(r'"user"[^}]*"name"\s*:\s*"([^"]+)"', context_str)
                    if not process_matches:
                        process_matches = re.findall(r'"process"[^}]*"name"\s*:\s*"([^"]+)"', context_str)
                    
                    # Method 3: Extract from reason field with "sshd" process
                    if not process_matches:
                        process_matches = re.findall(r'process\s+(\w+)', context_str)
                        if not process_matches:
                            # Look for sshd specifically
                            if 'sshd' in context_str.lower():
                                process_matches = ['sshd']
                    
                    # Remove duplicates and clean
                    ip_matches = list(set(ip_matches))
                    user_matches = list(set(user_matches))
                    process_matches = list(set(process_matches))
                    
                    # Create a simplified context with extracted IoCs
                    if ip_matches or user_matches or process_matches:
                        simplified_alerts = []
                        max_alerts = max(len(ip_matches), len(user_matches), len(process_matches), 1)
                        for i in range(min(10, max_alerts)):
                            alert = {}
                            if i < len(ip_matches):
                                alert["source"] = {"ip": ip_matches[i]}
                            if i < len(user_matches):
                                alert["user"] = {"name": user_matches[i]}
                            if i < len(process_matches):
                                alert["process"] = {"name": process_matches[i]}
                            if alert:
                                simplified_alerts.append(alert)
                        
                        if simplified_alerts:
                            result["context"] = {"alerts": simplified_alerts}
                            logger.info(f"Extracted {len(simplified_alerts)} simplified alerts with IoCs: IPs={ip_matches}, Users={user_matches}, Processes={process_matches}")
                        else:
                            # Fallback: store truncated raw string (max 10000 chars)
                            truncated = context_str[:10000] if len(context_str) > 10000 else context_str
                            result["context"] = {
                                "raw_malformed_data": truncated,
                                "note": f"Raw malformed context data (truncated from {len(context_str)} to {len(truncated)} chars) - LLM will extract IoCs"
                            }
                            logger.info(f"Storing truncated raw context string for LLM extraction ({len(truncated)} chars)")
                    else:
                        # No IoCs found with regex, store truncated raw string
                        truncated = context_str[:10000] if len(context_str) > 10000 else context_str
                        result["context"] = {
                            "raw_malformed_data": truncated,
                            "note": f"Raw malformed context data (truncated from {len(context_str)} to {len(truncated)} chars) - LLM will extract IoCs"
                        }
                        logger.info(f"Storing truncated raw context string for LLM extraction ({len(truncated)} chars)")
            else:
                logger.warning("Context value does not start with quote, using fallback")
                result["context"] = {"note": "Context data format not recognized"}
        
        # Ensure we have at least alert and rule (fallback if not found)
        if "alert" not in result:
            result["alert"] = {
                "id": "unknown-malformed-alert",
                "uuid": "unknown-malformed-alert",
                "actionGroup": "default",
                "actionGroupName": "Default",
                "flapping": False
            }
        
        if "rule" not in result:
            result["rule"] = {
                "id": "unknown-malformed",
                "name": "Unknown Malformed Alert",
                "type": "query",
                "spaceId": "default",
                "tags": ["malformed-alert-fallback"],
                "params": {
                    "description": "Malformed alert data - unable to parse",
                    "severity": "medium"
                }
            }
        
        if result:
            logger.info(f"Successfully parsed malformed alert with {len(result)} components")
            return result
        
    except Exception as e:
        logger.warning(f"Failed to parse malformed alert format: {str(e)}")
    
    return data


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
        # Process through initial pipeline steps (Rule-to-Text: IOC extraction + threat intel + translation)
        initial_pipeline = ["alert_processing", "ioc_extractor", "retrieval_engine", "translation_engine"]

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
        session_id = await chat_session_manager.create_session(
            natural_language_summary, analyst_ready_report, initial_result, alert_id, alert_data
        )

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
            "message": "Interactive chat session created. Use /chat/message to interact with the agent.",
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
                "analysis_type": "complete_llm_pipeline",
            },
            "pipeline_results": result,
            "llm_outputs": {
                "initial_summary": result.get("natural_language_summary"),
                "final_mcp_response": result.get("mcp_response"),
                "formatted_response": result.get("formatted_response"),
            },
            "extracted_intelligence": {
                "iocs": result.get("extracted_iocs", {}),
                "alert_details": result.get("processed_alert", {}),
                "analyst_report": result.get("analyst_ready_report", {}),
            },
        }

        # Save to file with pretty formatting
        with open(filename, "w", encoding="utf-8") as f:
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
        logger.info(
            f"Chat manager instance ID at completion: {id(chat_session_manager) if chat_session_manager else 'None'}"
        )
        logger.info(
            f"Available sessions in manager: {list(chat_session_manager.sessions.keys()) if chat_session_manager else 'No manager'}"
        )

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
            raise HTTPException(
                status_code=400, detail=f"Failed to end chat session: {chat_result.get('error')}"
            )

        report = chat_result.get("report", {})

        # Get the original alert context from the chat session
        natural_language_summary = report.get("rule_to_text_summary", "")
        analyst_ready_report = report.get("analyst_ready_report", {})
        conversation_history = report.get("conversation_history", [])
        recommended_playbooks = report.get("recommended_playbooks", [])
        final_recommendations = report.get("final_recommendations", [])

        logger.info(
            f"Retrieved chat report - Summary length: {len(natural_language_summary)}, Recommendations: {len(final_recommendations)}"
        )

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
                "playbook_count": len(recommended_playbooks),
            },
        }

        # Process through final pipeline steps
        final_pipeline = ["prompt_generation", "mcp_query", "response_formatting"]

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
            "pdf_download_url": (
                f"http://localhost:8001/chat/report/{chat_result.get('pdf_filename')}"
                if chat_result.get("pdf_filename")
                else None
            ),
            "summary": {
                "alert_id": alert_id,
                "chat_messages": len(report.get("conversation_history", [])),
                "playbooks_found": len(report.get("recommended_playbooks", [])),
                "recommendations": len(report.get("final_recommendations", [])),
                "completed_at": datetime.now().isoformat(),
            },
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
        with open(chat_file, "r", encoding="utf-8") as f:
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
            # Handle direct JSON data - supports both wrapped and raw Elastic format
            json_data = await request.json()
            
            # Try to parse malformed form-data-as-JSON-string format
            json_data = parse_malformed_elastic_alert(json_data)

            # Parse using the flexible AlertRequest model
            alert_request = AlertRequest.model_validate(json_data)
            
            # Get alert data whether it's wrapped or raw format
            alert_data_dict = alert_request.get_alert_data()
            
            # Convert to ElasticAlertData for processing
            elastic_data = ElasticAlertData.model_validate(alert_data_dict)

            logger.info("Processed JSON data")

        else:
            raise ValueError(f"Unsupported content type: {content_type}")

        # Prepare the initial data with the alert
        initial_data = {"alert_data": elastic_data.model_dump()}

        # Ensure agent manager is initialized before processing
        if agent_manager.mcp_client is None:
            logger.info("Agent manager not initialized, initializing now...")
            await agent_manager.initialize_mvc_agent()

        # Extract alert ID safely
        alert_id = elastic_data.alert.id if elastic_data.alert else "unknown"
        
        # Process alert in interactive mode (default behavior)
        initial_result = await process_alert_interactive_mode(initial_data, alert_id)

        # Add chat interface URL to the response
        chat_url = f"http://localhost:8001/chat_interface.html?alert_id={alert_id}&session_id={initial_result['session_id']}"
        initial_result["chat_interface_url"] = chat_url
        initial_result["instructions"] = (
            f"🔗 CHAT INTERFACE: {chat_url}\n\nOpen this URL in your browser to start the interactive chat session for this alert."
        )

        # Log the chat interface URL prominently
        logger.info(f"🔗 CHAT INTERFACE URL: {chat_url}")
        logger.info(f"📋 Alert ID: {alert_id}")
        logger.info(f"🔑 Session ID: {initial_result['session_id']}")
        print(f"\n🔗 CHAT INTERFACE: {chat_url}")
        print(f"📋 Alert ID: {alert_id}")
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
                    "alert_id": (
                        existing_session.alert_summary[:50] + "..."
                        if existing_session.alert_summary
                        else alert_id
                    ),
                    "alert_summary": existing_session.alert_summary,
                    "recommended_playbooks": existing_session.recommended_playbooks,
                    "existing_conversation": existing_session.conversation_history,
                }
            else:
                logger.warning(f"Session {session_id_param} not found, creating new session")
                # Fall through to create new session

        # Create a new session
        logger.info("Creating new chat session")
        if alert_id:
            # For existing alerts, use a more generic summary since we don't have the actual rule-to-text
            alert_summary = (
                f"Security alert {alert_id} detected. Please analyze and provide response recommendations."
            )
        else:
            alert_summary = "Security alert detected. Please analyze and provide response recommendations."

        analyst_report = {"executive_summary": "Initial alert analysis session started."}

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
            "existing_conversation": session.conversation_history,
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
            "total_count": chat_session_manager.get_session_count(),
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
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error serving PDF report: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error serving report: {str(e)}") from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
