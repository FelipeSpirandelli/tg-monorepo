from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from src.agent_manager import AgentManager
from src.logger import logger
from src.models import AgentResponse, AlertRequest


# Define lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing MVC agent...")
    try:
        await agent_manager.initialize_mvc_agent()
        logger.info("MVC agent initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize MVC agent: {str(e)}")
    yield
    agent_manager.mcp_client.cleanup()
    logger.info("MVC agent cleanup completed")


# Initialize the agent manager
agent_manager = AgentManager()

# Pass the lifespan to the FastAPI app
app = FastAPI(title="Agent Orchestrator", lifespan=lifespan)


@app.post("/alert", response_model=AgentResponse)
async def process_alert(request: AlertRequest):
    """
    Process an incoming alert through a configurable pipeline

    The pipeline can be customized by providing the pipeline_config field.
    If no pipeline is specified, the default pipeline will be used.
    """
    try:
        # Prepare the initial data with the alert
        initial_data = {"alert_data": request.alert_data.model_dump()}

        # Use custom pipeline if provided, otherwise use default
        if request.pipeline_config:
            pipeline_steps = request.pipeline_config.steps
            step_config = request.pipeline_config.step_config
            result = await agent_manager.pipeline_processor.process(initial_data, pipeline_steps, step_config)
        else:
            # Use default pipeline
            result = await agent_manager.process_alert(initial_data)

        return AgentResponse(response=result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
