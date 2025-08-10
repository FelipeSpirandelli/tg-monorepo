# TG

This monorepo contains an AI-powered application system with integrated tools and pipeline-based processing.

## Architecture Overview

The system is composed of a single, consolidated component:

```
┌──────────────────────────────────────────────┐
│               Agent Orchestrator             │
│  ┌─────────────────┐  ┌─────────────────────┐ │
│  │ FastAPI Server  │  │   Integrated MCP    │ │
│  │ (Webhook/API)   │  │      Tools          │ │
│  └─────────────────┘  └─────────────────────┘ │
│  ┌─────────────────┐  ┌─────────────────────┐ │
│  │ Pipeline        │  │   AI Agent          │ │
│  │ Processor       │  │  (Claude + Tools)   │ │
│  └─────────────────┘  └─────────────────────┘ │
└──────────────────────────────────────────────┘
```

### Component

**Agent Orchestrator**
A unified service that handles:

- **Webhook/API Reception**: Receives external requests via FastAPI
- **Pipeline Processing**: Processes alerts through configurable pipeline steps
- **AI Agent Coordination**: Uses Claude with integrated MCP tools
- **Tool Integration**: Built-in cybersecurity analysis tools (IP lookup, port analysis, threat assessment, etc.)

## Data Flow

1. External systems send requests to the Agent Orchestrator API endpoints
2. The Agent Orchestrator processes requests through a configurable pipeline:
   - Alert processing and normalization
   - Prompt generation with context
   - AI agent query with integrated tools
   - Response formatting
3. The AI agent can use built-in tools for enhanced analysis:
   - IP reputation lookup
   - Port threat analysis
   - Historical pattern matching
   - Comprehensive threat assessment

## Development

The system is now contained in a single directory:

- `/agent-orchestrator` - The unified AI orchestration service with integrated tools

## Getting Started

To run the system:

1. Navigate to the agent-orchestrator directory
2. Install dependencies: `uv sync` or `pip install -e .`
3. Set up environment variables (ANTHROPIC_API_KEY)
4. Start the service: `python main.py`

The service will start on port 8001 and be ready to receive webhook requests and process alerts.

Refer to the README in the agent-orchestrator directory for detailed usage instructions.
