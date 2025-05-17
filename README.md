# TG

This monorepo contains a set of interconnected services that work together to provide an AI-powered application system.

## Architecture Overview

The system is composed of the following components:

```
┌─────────────────┐      ┌────────────────────┐      ┌────────────┐
│ Webhook Receiver│ ───> │ Agent Orchestrator │ ───> │ Server API │
└─────────────────┘      └────────────────────┘      └────────────┘
```

### Components

1. **Webhook Receiver**  
   Serves as the entry point for external events. It receives webhooks from various sources and forwards the appropriate data to the Agent Orchestrator.

2. **Agent Orchestrator**  
   The core component responsible for:

   - Processing incoming webhook data
   - Coordinating AI agent activities using LangChain
   - Executing necessary business logic
   - Communicating with the Server API to persist or retrieve data

3. **Server API (MVC)**  
   A model-view-controller backend that:
   - Provides data persistence
   - Handles business logic
   - Exposes RESTful endpoints for the Agent Orchestrator to consume

## Data Flow

1. External systems trigger webhooks to the Webhook Receiver
2. The Webhook Receiver processes and forwards relevant data to the Agent Orchestrator
3. The Agent Orchestrator:
   - Analyzes the incoming data
   - Makes decisions using AI capabilities
   - Calls appropriate endpoints on the Server API
4. The Server API processes requests, performs database operations, and returns necessary data

## Development

Each component is located in its own directory within this monorepo:

- `/webhook-receiver` - The webhook handling service
- `/agent-orchestrator` - The LangChain-based AI orchestration service
- `/server-api` - The MVC backend

## Getting Started

To run the entire system:

1. Install dependencies for each component
2. Start each service in the recommended order:
   - Server API
   - Agent Orchestrator
   - Webhook Receiver

Refer to the README in each component directory for specific setup instructions.
