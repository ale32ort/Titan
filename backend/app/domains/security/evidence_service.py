from sqlalchemy import select
from sqlalchemy.orm import Session
from app.domains.security.models import AuditEvent
from app.domains.security.evidence import FindingEvidence


def attach_audit_event_evidence(
    db: Session,
    *,
    finding_id: str,
    audit_event_id: str,
) -> FindingEvidence:
    existing = db.scalar(
        select(FindingEvidence).where(
            FindingEvidence.finding_id == finding_id,
            FindingEvidence.audit_event_id == audit_event_id,
        )
    )

    if existing:
        return existing

    evidence = FindingEvidence(
        finding_id=finding_id,
        audit_event_id=audit_event_id,
    )

    db.add(evidence)
    db.commit()
    db.refresh(evidence)

    return evidence

def get_finding_audit_events(
    db: Session,
    *,
    finding_id: str,
) -> list[AuditEvent]:
    """Return the audit events linked to a security finding."""

    events = db.scalars(
        select(AuditEvent)
        .join(
            FindingEvidence,
            FindingEvidence.audit_event_id == AuditEvent.id,
        )
        .where(
            FindingEvidence.finding_id == finding_id,
        )
        .order_by(AuditEvent.created_at.asc())
    ).all()

    return list(events)

