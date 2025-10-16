import json
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ElasticAlert(BaseModel):
    """Elastic alert model extracted from form_data"""

    id: str = Field(..., description="Alert ID")
    uuid: str = Field(..., description="Alert UUID")
    action_group: str = Field(..., alias="actionGroup", description="Action group")
    action_group_name: str = Field(..., alias="actionGroupName", description="Action group name")
    flapping: bool = Field(..., description="Whether the alert is flapping")
    consecutive_matches: int = Field(
        ..., alias="consecutiveMatches", description="Number of consecutive matches"
    )


class ElasticRuleParams(BaseModel):
    """Elastic rule parameters"""

    author: list[str] | None = Field(default=None, description="Rule authors")
    description: str = Field(..., description="Rule description")
    note: str | None = Field(default=None, description="Rule note")
    false_positives: list[str] = Field(
        default_factory=list, alias="falsePositives", description="False positives"
    )
    from_: str = Field(alias="from", description="Time range from")
    rule_id: str = Field(..., alias="ruleId", description="Rule ID")
    immutable: bool = Field(..., description="Whether the rule is immutable")
    license: str = Field(..., description="License")
    output_index: str = Field(default="", alias="outputIndex", description="Output index")
    meta: dict[str, Any] = Field(default_factory=dict, description="Rule metadata")
    max_signals: int = Field(..., alias="maxSignals", description="Maximum signals")
    risk_score: int = Field(..., alias="riskScore", description="Risk score")
    risk_score_mapping: list[Any] = Field(
        default_factory=list, alias="riskScoreMapping", description="Risk score mapping"
    )
    severity: str = Field(..., description="Rule severity")
    severity_mapping: list[Any] = Field(
        default_factory=list, alias="severityMapping", description="Severity mapping"
    )
    threat: list[dict[str, Any]] = Field(default_factory=list, description="Threat information")
    to: str = Field(..., description="Time range to")
    references: list[str] = Field(default_factory=list, description="References")
    version: int = Field(..., description="Rule version")
    exceptions_list: list[Any] = Field(
        default_factory=list, alias="exceptionsList", description="Exceptions list"
    )
    related_integrations: list[dict[str, str]] = Field(
        default_factory=list, alias="relatedIntegrations", description="Related integrations"
    )
    required_fields: list[dict[str, Any]] = Field(
        default_factory=list, alias="requiredFields", description="Required fields"
    )
    setup: str | None = Field(default=None, description="Setup instructions")
    type: str = Field(..., description="Rule type")
    language: str = Field(..., description="Query language")
    index: list[str] = Field(default_factory=list, description="Indices")
    query: str = Field(..., description="Rule query")
    filters: list[Any] = Field(default_factory=list, description="Filters")


class ElasticRule(BaseModel):
    """Elastic rule model extracted from form_data"""

    params: ElasticRuleParams = Field(..., description="Rule parameters")
    id: str = Field(..., description="Rule ID")
    name: str = Field(..., description="Rule name")
    type: str = Field(..., description="Rule type")
    url: str = Field(..., description="Rule URL")
    tags: list[str] = Field(default_factory=list, description="Rule tags")
    space_id: str = Field(..., alias="spaceId", description="Space ID")


class ElasticAlertData(BaseModel):
    """Complete alert data from Elastic including metadata and extracted form data"""

    timestamp: str | None = Field(default=None, description="Alert timestamp")
    method: str | None = Field(default=None, description="HTTP method")
    headers: dict[str, str] | None = Field(default=None, description="HTTP headers")
    url: str | None = Field(default=None, description="Request URL")
    remote_addr: str | None = Field(default=None, description="Remote address")
    user_agent: str | None = Field(default=None, description="User agent")
    form_data: dict[str, list[str]] | None = Field(default=None, description="Raw form data")

    # Parsed form data
    alert: ElasticAlert | None = Field(default=None, description="Parsed alert data")
    rule: ElasticRule | None = Field(default=None, description="Parsed rule data")

    @field_validator("alert", mode="before")
    @classmethod
    def parse_alert(cls, v, info):
        """Parse alert from form_data if not already parsed"""
        if v is not None:
            return v

        form_data = info.data.get("form_data", {})
        # Look for the alert key in form_data
        for key, _ in form_data.items():
            try:
                # Parse the key as JSON to find the alert data
                parsed_key = json.loads(key)
                if "alert" in parsed_key:
                    alert_json = parsed_key["alert"]
                    if isinstance(alert_json, str):
                        return ElasticAlert.model_validate(json.loads(alert_json))
                    else:
                        return ElasticAlert.model_validate(alert_json)
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return None

    @field_validator("rule", mode="before")
    @classmethod
    def parse_rule(cls, v, info):
        """Parse rule from form_data if not already parsed"""
        if v is not None:
            return v

        form_data = info.data.get("form_data", {})
        # Look for the rule key in form_data
        for key, _ in form_data.items():
            try:
                # Parse the key as JSON to find the rule data
                parsed_key = json.loads(key)
                if "rule" in parsed_key:
                    rule_json = parsed_key["rule"]
                    if isinstance(rule_json, str):
                        return ElasticRule.model_validate(json.loads(rule_json))
                    else:
                        return ElasticRule.model_validate(rule_json)
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
        return None


class AlertRequest(BaseModel):
    """Request model for alert processing"""

    alert_data: ElasticAlertData = Field(..., description="The Elastic alert data to process")
    interactive: bool = Field(default=True, description="Enable interactive chat mode for SOC analyst (default: True)")


class AgentResponse(BaseModel):
    """Response model for agent queries and alert processing"""

    response: dict[str, Any] = Field(..., description="Response data")
