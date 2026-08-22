from sqlalchemy.orm import Session

from app.domains.security.models import AuditEvent


def record_audit_event(
    db: Session,
    *,
    event_type: str,
    result: str,
    user_id: str | None = None,
    email: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    event_metadata: dict | None = None,
) -> AuditEvent:
    """Persist a security-relevant audit event."""

    event = AuditEvent(
        event_type=event_type,
        result=result,
        user_id=user_id,
        email=email,
        ip_address=ip_address,
        user_agent=user_agent,
        event_metadata=event_metadata,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    return event