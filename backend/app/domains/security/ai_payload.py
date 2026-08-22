from dataclasses import asdict, dataclass
from typing import Any

from app.domains.security.triage import TriageContext
from app.domains.security.triage_analysis import TriageAnalysis
from app.domains.security.triage_result import TriageResult


@dataclass(frozen=True)
class AIInputPayload:
    finding_id: str
    finding_type: str
    subject: str
    severity: str
    status: str

    rule: dict[str, Any] | None

    analysis: dict[str, Any]

    deterministic_result: dict[str, Any]

    evidence: list[dict[str, Any]]


def build_ai_input_payload(
    context: TriageContext,
    analysis: TriageAnalysis,
    result: TriageResult,
) -> AIInputPayload:
    rule_payload = (
        asdict(context.rule)
        if context.rule
        else None
    )

    evidence_payload = [
        {
            "event_id": event.event_id,
            "event_type": event.event_type,
            "email": event.email,
            "ip_address": event.ip_address,
            "result": event.result,
            "created_at": event.created_at.isoformat(),
        }
        for event in context.evidence
    ]

    return AIInputPayload(
        finding_id=context.finding_id,
        finding_type=context.finding_type,
        subject=context.subject,
        severity=context.severity,
        status=context.status,
        rule=rule_payload,
        analysis=asdict(analysis),
        deterministic_result=asdict(result),
        evidence=evidence_payload,
    )