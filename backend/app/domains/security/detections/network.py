from sqlalchemy.orm import Session

from app.domains.security.evidence_service import (
    attach_audit_event_evidence,
)
from app.domains.security.finding_service import (
    upsert_security_finding,
)
from app.domains.security.models import AuditEvent
from app.domains.security.rules import NET_001


RECON_KEYWORDS = (
    "recon",
    "reconnaissance",
    "scan",
    "scanner",
    "nmap",
    "port scan",
)


def detect_network_reconnaissance(
    db: Session,
    *,
    event_id: str,
) -> bool:
    """
    Detect reconnaissance activity from an ingested
    Suricata alert.

    The ingested AuditEvent is the anchor evidence.
    """

    event = db.get(
        AuditEvent,
        event_id,
    )

    if event is None:
        return False

    if (
        event.event_type
        != "SENSOR_SURICATA_ALERT"
    ):
        return False

    metadata = (
        event.event_metadata
        or {}
    )

    message = str(
        metadata.get("message")
        or ""
    ).lower()

    source_metadata = (
        metadata.get("source_metadata")
        or {}
    )

    source_text = " ".join(
        str(value)
        for value in source_metadata.values()
    ).lower()

    combined_text = (
        f"{message} {source_text}"
    )

    if not any(
        keyword in combined_text
        for keyword in RECON_KEYWORDS
    ):
        return False

    source_ip = (
        metadata.get("source_ip")
        or event.ip_address
        or "unknown-source"
    )

    finding = upsert_security_finding(
        db,
        finding_type="NETWORK_RECONNAISSANCE",
        subject=str(source_ip),
        severity=NET_001.severity,
        rule_id=NET_001.rule_id,
    )

    attach_audit_event_evidence(
        db,
        finding_id=finding.id,
        audit_event_id=event.id,
    )

    return True