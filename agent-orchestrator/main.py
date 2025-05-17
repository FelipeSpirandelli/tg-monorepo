from agent_manager import AgentManager
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Agent Orchestrator")
agent_manager = AgentManager()


# Initialize the MVC agent on startup
@app.on_event("startup")
async def startup_event():
    try:
        agent_manager.initialize_mvc_agent()
    except Exception as e:
        print(f"Failed to initialize MVC agent: {str(e)}")


class AgentQuery(BaseModel):
    query: str
    agent_name: str = "mvc_agent"  # Default to MVC agent


class AgentResponse(BaseModel):
    response: str


@app.post("/query", response_model=AgentResponse)
async def query_agent(request: AgentQuery):
    """Run a query through the specified agent"""
    try:
        response = agent_manager.run_agent(request.agent_name, request.query)
        return AgentResponse(response=response)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing query: {str(e)}")


@app.get("/agents")
async def list_agents():
    """List all available agents"""
    return {"agents": list(agent_manager.agents.keys())}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)
