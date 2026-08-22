from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.security.models import AuditEvent
from app.domains.security.finding_service import (
    upsert_security_finding,
)
from app.domains.security.evidence_service import (
    attach_audit_event_evidence,
)
from app.domains.security.rules import (
    AUTH_001,
    AUTH_002,
    AUTH_003,
)


def detect_repeated_login_failures(
    db: Session,
    email: str,
) -> bool:
    """Detect repeated failed authentication attempts for one account."""

    window_start = (
        datetime.now(timezone.utc)
        - timedelta(minutes=AUTH_001.window_minutes)
    )

    failed_events = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.event_type == "LOGIN_FAILED",
            AuditEvent.email == email,
            AuditEvent.created_at >= window_start,
        )
        .order_by(AuditEvent.created_at.asc())
    ).all()

    failed_attempts = len(failed_events)

    if failed_attempts < AUTH_001.threshold:
        return False

    finding = upsert_security_finding(
        db,
        finding_type="AUTH_BRUTE_FORCE_SUSPECTED",
        subject=email,
        severity=AUTH_001.severity,
        rule_id=AUTH_001.rule_id,
    )

    for event in failed_events:
        attach_audit_event_evidence(
            db,
            finding_id=finding.id,
            audit_event_id=event.id,
        )

    return True


def detect_password_spray(
    db: Session,
    ip_address: str | None,
) -> bool:
    """
    Detect failed authentication attempts from one IP
    against multiple distinct accounts.
    """

    if not ip_address:
        return False

    window_start = (
        datetime.now(timezone.utc)
        - timedelta(minutes=AUTH_002.window_minutes)
    )

    failed_events = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.event_type == "LOGIN_FAILED",
            AuditEvent.ip_address == ip_address,
            AuditEvent.email.is_not(None),
            AuditEvent.created_at >= window_start,
        )
        .order_by(AuditEvent.created_at.asc())
    ).all()

    targeted_accounts = {
        event.email
        for event in failed_events
        if event.email
    }

    if len(targeted_accounts) < AUTH_002.threshold:
        return False

    finding = upsert_security_finding(
        db,
        finding_type="PASSWORD_SPRAY_SUSPECTED",
        subject=ip_address,
        severity=AUTH_002.severity,
        rule_id=AUTH_002.rule_id,
    )

    for event in failed_events:
        attach_audit_event_evidence(
            db,
            finding_id=finding.id,
            audit_event_id=event.id,
        )

    return True

def detect_success_after_failures(
    db: Session,
    *,
    email: str,
    success_event_id: str,
) -> bool:
    """
    Detect a successful authentication following repeated
    failed attempts against the same account.
    """

    window_start = (
        datetime.now(timezone.utc)
        - timedelta(minutes=AUTH_003.window_minutes)
    )

    failed_events = db.scalars(
        select(AuditEvent)
        .where(
            AuditEvent.event_type == "LOGIN_FAILED",
            AuditEvent.email == email,
            AuditEvent.created_at >= window_start,
        )
        .order_by(AuditEvent.created_at.asc())
    ).all()

    if len(failed_events) < AUTH_003.threshold:
        return False

    success_event = db.get(
        AuditEvent,
        success_event_id,
    )

    if success_event is None:
        return False

    finding = upsert_security_finding(
        db,
        finding_type="SUCCESS_AFTER_REPEATED_FAILURES",
        subject=email,
        severity=AUTH_003.severity,
        rule_id=AUTH_003.rule_id,
    )

    for event in failed_events:
        attach_audit_event_evidence(
            db,
            finding_id=finding.id,
            audit_event_id=event.id,
        )

    attach_audit_event_evidence(
        db,
        finding_id=finding.id,
        audit_event_id=success_event.id,
    )

    return True