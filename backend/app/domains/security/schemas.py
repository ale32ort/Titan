from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from typing import Literal

from pydantic import BaseModel


class AITriageOutputPublic(BaseModel):
    executive_summary: str
    analyst_assessment: str
    confirmed_facts: list[str]
    hypotheses: list[str]
    missing_context: list[str]
    recommended_actions: list[str]
    confidence: Literal["low", "medium", "high"]
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
    model_config = ConfigDict(from_attributes=True)

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
    model_config = ConfigDict(from_attributes=True)

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


class SecurityFindingDetail(SecurityFindingPublic):
    rule: DetectionRulePublic | None
    evidence_count: int
    evidence: list[AuditEventEvidencePublic]
    assigned_to_user_id: str | None = None


class SecurityFindingStatusUpdate(BaseModel):
    status: str


class AITriageRunPublic(BaseModel):
    id: str
    finding_id: str
    requested_by_user_id: str | None
    provider: str
    model: str

    executive_summary: str
    analyst_assessment: str
    confirmed_facts: list[str]
    hypotheses: list[str]
    missing_context: list[str]
    recommended_actions: list[str]

    confidence: Literal["low", "medium", "high"]

    compromise_status: Literal[
        "not_established",
        "suspected",
        "confirmed",
    ]

    grounding_corrections: list[str]

    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AnalystNoteCreate(BaseModel):
    content: str


class AnalystNotePublic(BaseModel):
    id: str
    finding_id: str
    author_user_id: str
    content: str
    created_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )

class CaseTimelineItem(BaseModel):
    event_type: str
    title: str
    description: str
    actor_user_id: str | None = None
    created_at: datetime
    metadata: dict = Field(
        default_factory=dict
    )