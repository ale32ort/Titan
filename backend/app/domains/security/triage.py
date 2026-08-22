from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.domains.security.evidence_service import get_finding_audit_events
from app.domains.security.findings import SecurityFinding
from app.domains.security.rules import DetectionRule, get_detection_rule


@dataclass(frozen=True)
class TriageEvidence:
    event_id: str
    event_type: str
    email: str | None
    ip_address: str | None
    user_agent: str | None
    result: str
    event_metadata: dict[str, Any] | None
    created_at: datetime


@dataclass(frozen=True)
class TriageContext:
    finding_id: str
    finding_type: str
    subject: str
    severity: str
    status: str
    trigger_count: int
    evidence_count: int
    first_seen: datetime
    last_seen: datetime
    rule: DetectionRule | None
    evidence: list[TriageEvidence]


def build_triage_context(
    db: Session,
    *,
    finding: SecurityFinding,
) -> TriageContext:
    audit_events = get_finding_audit_events(
        db,
        finding_id=finding.id,
    )

    rule = (
        get_detection_rule(finding.rule_id)
        if finding.rule_id
        else None
    )

    evidence = [
        TriageEvidence(
            event_id=event.id,
            event_type=event.event_type,
            email=event.email,
            ip_address=event.ip_address,
            user_agent=event.user_agent,
            result=event.result,
            event_metadata=event.event_metadata,
            created_at=event.created_at,
        )
        for event in audit_events
    ]

    return TriageContext(
        finding_id=finding.id,
        finding_type=finding.finding_type,
        subject=finding.subject,
        severity=finding.severity,
        status=finding.status,
        trigger_count=finding.trigger_count,
        evidence_count=len(evidence),
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        rule=rule,
        evidence=evidence,
    )