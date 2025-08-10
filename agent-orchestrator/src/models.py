from typing import Any

from pydantic import BaseModel, Field


class AlertData(BaseModel):
    """Alert data model"""

    type: str = Field(..., description="Type of the alert")
    source: str = Field(..., description="Source of the alert")
    severity: str = Field(default="medium", description="Severity of the alert")
    timestamp: str | None = Field(None, description="Timestamp of the alert")
    details: dict[str, Any] = Field(
        default_factory=dict, description="Additional details of the alert"
    )


class AlertRequest(BaseModel):
    """Request model for alert processing"""

    alert_data: AlertData = Field(..., description="The alert data to process")


class AgentResponse(BaseModel):
    """Response model for agent queries and alert processing"""

    response: dict[str, Any] = Field(..., description="Response data")
