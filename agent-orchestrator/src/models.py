from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class AlertData(BaseModel):
    """Alert data model"""

    type: str = Field(..., description="Type of the alert")
    source: str = Field(..., description="Source of the alert")
    severity: str = Field(default="medium", description="Severity of the alert")
    timestamp: Optional[str] = Field(None, description="Timestamp of the alert")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details of the alert")


class PipelineConfig(BaseModel):
    """Configuration for a pipeline run"""

    steps: List[str] = Field(..., description="List of pipeline step names to execute in order")
    step_config: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict, description="Configuration for individual pipeline steps"
    )


class AlertRequest(BaseModel):
    """Request model for alert processing"""

    alert_data: AlertData = Field(..., description="The alert data to process")
    pipeline_config: Optional[PipelineConfig] = Field(
        None, description="Optional custom pipeline configuration"
    )


class AgentResponse(BaseModel):
    """Response model for agent queries and alert processing"""

    response: Dict[str, Any] = Field(..., description="Response data")
