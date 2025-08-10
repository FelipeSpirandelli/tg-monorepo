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
async def process_alert(request: AlertRequest):
    """
    Process an incoming alert through the default pipeline
    """
    try:
        # Prepare the initial data with the alert
        initial_data = {"alert_data": request.alert_data.model_dump()}

        # Use default pipeline
        result = await agent_manager.process_alert(initial_data)

        return AgentResponse(response=result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing alert: {str(e)}") from e


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8001)
