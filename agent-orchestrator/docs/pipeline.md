# Agent Orchestrator Pipeline Architecture

## Overview

The Agent Orchestrator is designed with a flexible pipeline architecture that processes alert data through configurable steps. This design allows for:

- Easily extendable processing steps
- Customizable data flow between pipeline stages
- Dynamic prompt generation based on alert context
- Integration with MCP tools and external services

## Pipeline Structure

The pipeline consists of modular steps that can be arranged in different sequences:

```
┌────────────────┐      ┌────────────────────┐      ┌───────────────┐      ┌─────────────────────┐
│ Alert          │  →   │ Prompt             │  →   │ MCP Query     │  →   │ Response            │
│ Processing     │      │ Generation         │      │ Execution     │      │ Formatting          │
└────────────────┘      └────────────────────┘      └───────────────┘      └─────────────────────┘
```

Each pipeline step:

1. Receives a data dictionary from previous steps
2. Processes the data according to its logic
3. Returns additional data to be passed to subsequent steps

## Core Pipeline Steps

### 1. Alert Processing

- Extracts and normalizes relevant information from raw alerts
- Classifies and prioritizes alerts based on type and severity

### 2. Prompt Generation

- Creates contextual prompts for the AI based on processed alert data
- Can be customized with templates to guide specific responses

### 3. MCP Query Execution

- Connects to MCP-enabled AI models
- Provides tools access to the model for enhanced reasoning
- Manages the conversation flow with the model

### 4. Response Formatting

- Structures AI responses in a consistent format
- Extracts key information and recommendations

## Extending the Pipeline

You can easily extend the pipeline by:

1. Creating custom pipeline steps that inherit from `PipelineStep`
2. Registering your step with the `PipelineProcessor`
3. Including your step in a custom pipeline configuration

See `examples/custom_pipeline_step.py` for an example implementation.

## Usage

### Basic Usage

```python
# Create a request with alert data
alert_request = AlertRequest(
    alert_data=AlertData(
        type="security_alert",
        source="intrusion_detection_system",
        severity="high",
        timestamp="2025-05-24T15:30:45Z",
        details={...}
    )
)

# Send to API endpoint
response = await client.post("http://localhost:8001/alert", json=alert_request.dict())
```

### Custom Pipeline

```python
# Define custom pipeline configuration
alert_request = AlertRequest(
    alert_data=AlertData(...),
    pipeline_config=PipelineConfig(
        steps=["alert_processing", "custom_step", "prompt_generation", "mcp_query", "response_formatting"],
        step_config={
            "prompt_generation": {
                "prompt_template": "Custom prompt template here..."
            }
        }
    )
)
```

## Pipeline Data Flow

Each step can define:

- `required_inputs`: Keys that must be present in the input data
- `provided_outputs`: Keys that the step will add to the output data

This ensures that each step has the data it needs, and that data flows correctly through the pipeline.
