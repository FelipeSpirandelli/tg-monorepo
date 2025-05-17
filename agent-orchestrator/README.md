# MVC API LangChain Agent

This service provides a LangChain-powered agent that can communicate with and perform operations on the MVC API service.

## Setup

2. Set up your OpenAI API key:

```bash
export OPENAI_API_KEY=your_api_key_here
```

3. Update the configuration in `config.py` to point to your actual MVC API endpoint.

## Running the Service

Start the agent orchestrator:

```bash
python main.py
```

The service will run on http://localhost:8001.

## Using the Agent

Send queries to the agent using the API endpoint:

```bash
curl -X POST http://localhost:8001/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Get all users from the MVC API"}'
```

## Example Queries

The agent can handle various operations on the MVC API:

- "Get a list of all users"
- "Get user details for user with ID 123"
- "Create a new user with name 'John Doe' and email 'john@example.com'"
- "Update user 456 to have a new email address: jane@example.com"
- "Delete user with ID 789"

## Extending the Agent

To add more capabilities to the agent, modify the `MVCAPITool` class in `langchain_mvc_agent.py`.
