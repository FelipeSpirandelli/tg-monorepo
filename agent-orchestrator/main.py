from contextlib import asynccontextmanager

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

# Pass the lifespan to the FastAPI app
app = FastAPI(title="Agent Orchestrator", lifespan=lifespan)


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
