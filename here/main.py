import json
import os
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request

from src.agent_manager import AgentManager
from src.logger import logger
from src.models import AgentResponse, AlertRequest, ElasticAlertData


# Define lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing MVC agent...")
    try:
        await agent_manager.initialize_mvc_agent()
    except Exception as e:
        logger.error(f"Failed to initialize MVC agent: {str(e)}")
    yield
    await agent_manager.mcp_client.cleanup()
    logger.info("Integrated MCP client cleanup completed")


# Initialize the agent manager
agent_manager = AgentManager()


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

        # Use default pipeline
        result = await agent_manager.process_alert(initial_data)

        # Save complete results to file for analysis
        await save_complete_results_to_file(result, elastic_data.alert.id)

        return AgentResponse(response=result)

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error processing alert: {str(e)}")
        import traceback

        logger.error(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}") from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
