# Agent Orchestrator

A unified AI-powered system for processing alerts with integrated tools and pipeline-based architecture. This service combines webhook reception, AI agent coordination, and cybersecurity analysis tools in a single, consolidated application.

## Features

- **Unified Architecture**: Single service handles API requests, AI processing, and tool integration
- **Integrated MCP Tools**: Built-in cybersecurity analysis tools (no external MCP server needed)
- **Flexible Pipeline**: Extendable pipeline architecture for alert processing
- **Dynamic Prompting**: Context-aware prompt generation based on alert data
- **AI Agent Integration**: Claude integration with tool-calling capabilities
- **FastAPI Server**: RESTful API for receiving webhooks and processing requests

## Built-in Tools

The system includes several integrated analysis tools:

- **IP Lookup**: Reputation and geolocation analysis for IP addresses
- **Port Analyzer**: Threat assessment for network ports
- **Historical Data**: Pattern matching against historical incidents
- **Threat Assessment**: Comprehensive threat scoring and recommendations

## Getting Started

### Prerequisites

- Python 3.11+
- Required Python packages (listed in pyproject.toml)

### Installation

1. Navigate to the agent-orchestrator directory
2. Install dependencies:

```bash
cd agent-orchestrator
uv sync
# or
pip install -e .
```

3. Set up environment variables in a `.env` file:

```
ANTHROPIC_API_KEY=your_api_key_here
```

### Running the service

```bash
python main.py
```

The service will start on port 8001 and provides the following endpoints:

- `POST /alert` - Process alert data through the AI pipeline

## Usage

### Processing Alerts

Send a POST request to `/alert` with alert data:

```python
import httpx

response = await httpx.post(
    "http://localhost:8001/alert",
    json={
        "alert_data": {
            "type": "security_alert",
            "source": "intrusion_detection_system",
            "severity": "high",
            "timestamp": "2025-05-24T15:30:45Z",
            "details": {
                "ip_address": "192.168.1.100",
                "event_id": "IDS-1234",
                "rule_triggered": "Suspicious Login Attempt"
            }
        }
    }
)
```

### Customizing the Pipeline

You can customize the pipeline by providing a pipeline configuration:

```python
response = await httpx.post(
    "http://localhost:8001/alert",
    json={
        "alert_data": {...},
        "pipeline_config": {
            "steps": [
                "alert_processing",
                "custom_step",  # Your custom step
                "prompt_generation",
                "mcp_query"
            ],
            "step_config": {
                "prompt_generation": {
                    "prompt_template": "Your custom prompt template here"
                },
                "mcp_query": {
                    "model": "claude-3-5-sonnet-20241022",
                    "max_tokens": 1500,
                    "temperature": 0.2
                }
            }
        }
    }
)
```

## Extending the Pipeline

Create custom pipeline steps by inheriting from `PipelineStep`:

```python
from src.pipeline_processor import PipelineStep

class YourCustomStep(PipelineStep):
    @property
    def required_inputs(self):
        return ["processed_alert"]

    @property
    def provided_outputs(self):
        return ["custom_data"]

    async def process(self, data):
        # Your custom processing logic here
        return {"custom_data": result}
```

Register your step in `examples/register_custom_steps.py`.

## Architecture

See [docs/pipeline.md](docs/pipeline.md) for detailed pipeline architecture information.

## Examples

Check the `examples` directory for sample code:

- `send_alert.py` - Basic alert processing example
- `complex_alert.py` - Advanced pipeline configuration
- `custom_pipeline_step.py` - Creating custom pipeline steps
