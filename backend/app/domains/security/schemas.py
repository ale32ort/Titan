from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class AITriageOutputPublic(BaseModel):
    executive_summary: str
    analyst_assessment: str
    confirmed_facts: list[str]
    hypotheses: list[str]
    missing_context: list[str]
    recommended_actions: list[str]
    confidence: Literal[
        "low",
        "medium",
        "high",
    ]
    compromise_status: Literal[
        "not_established",
        "suspected",
        "confirmed",
    ]


class AITriageResponse(BaseModel):
    triage_run_id: str
    finding_id: str
    deterministic_summary: str
    ai_result: AITriageOutputPublic
    grounding_corrections: list[str]


class AuditEventEvidencePublic(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str
    event_type: str
    user_id: str | None
    email: str | None
    result: str
    ip_address: str | None
    user_agent: str | None
    event_metadata: dict[str, Any] | None
    created_at: datetime


class DetectionRulePublic(BaseModel):
    rule_id: str
    name: str
    description: str
    severity: str
    threshold: int | None
    window_minutes: int | None
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None


class SecurityFindingPublic(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: str
    finding_type: str
    subject: str
    severity: str
    status: str
    trigger_count: int
    rule_id: str | None
    first_seen: datetime
    last_seen: datetime
    assigned_to_user_id: str | None = None


class SecurityFindingDetail(
    SecurityFindingPublic
):
    rule: DetectionRulePublic | None
    evidence_count: int
    evidence: list[
        AuditEventEvidencePublic
    ]
    assigned_to_user_id: str | None = None


class SecurityFindingStatusUpdate(
    BaseModel
):
    status: str


class AITriageRunPublic(BaseModel):
    id: str
    finding_id: str
    requested_by_user_id: str | None
    provider: str
    model: str

    status: Literal[
        "running",
        "completed",
        "failed",
    ]

    error_type: str | None = None
    error_message: str | None = None

    executive_summary: str | None = None
    analyst_assessment: str | None = None
    confirmed_facts: list[str] | None = None
    hypotheses: list[str] | None = None
    missing_context: list[str] | None = None
    recommended_actions: list[str] | None = None

    confidence: Literal[
        "low",
        "medium",
        "high",
    ] | None = None

    compromise_status: Literal[
        "not_established",
        "suspected",
        "confirmed",
    ] | None = None

    grounding_corrections: list[str] | None = None

    created_at: datetime
    completed_at: datetime | None = None

    model_config = ConfigDict(
        from_attributes=True
    )


class AnalystNoteCreate(BaseModel):
  content: str


class AnalystNotePublic(BaseModel):
    id: str
    finding_id: str
    author_user_id: str
    content: str
    created_at: datetime

class CaseTimelineItem(BaseModel):
    event_type: str
    title: str
    description: str
    actor_user_id: str | None = None
    created_at: datetime
    metadata: dict = Field(
        default_factory=dict
    )


class SensorEventIngest(BaseModel):
    source: Literal[
        "suricata",
        "sysmon",
    ]

    event_type: str = Field(
        min_length=1,
        max_length=100,
    )

    host: str | None = Field(
        default=None,
        max_length=255,
    )

    source_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    destination_ip: str | None = Field(
        default=None,
        max_length=45,
    )

    severity: str | None = Field(
        default=None,
        max_length=20,
    )

    message: str | None = Field(
        default=None,
        max_length=2000,
    )

    observed_at: datetime | None = None

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )


class SensorEventIngestResponse(
    BaseModel
):
    event_id: str
    source: str
    event_type: str
    status: Literal["accepted"]
    created_at: datetime