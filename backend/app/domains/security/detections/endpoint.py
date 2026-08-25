from sqlalchemy.orm import Session

from app.domains.security.evidence_service import (
    attach_audit_event_evidence,
)
from app.domains.security.finding_service import (
    upsert_security_finding,
)
from app.domains.security.models import AuditEvent
from app.domains.security.rules import ENDPOINT_001


SUSPICIOUS_POWERSHELL_PATTERNS = (
    "-enc",
    "-encodedcommand",
    "frombase64string",
    "downloadstring",
    "invoke-webrequest",
    "iwr ",
    "iex ",
    "invoke-expression",
)


def detect_suspicious_powershell(
    db: Session,
    *,
    event_id: str,
) -> bool:
    """
    Detect suspicious PowerShell execution from
    an ingested Sysmon process event.
    """

    event = db.get(
        AuditEvent,
        event_id,
    )

    if event is None:
        return False

    if event.event_type != "SENSOR_SYSMON_PROCESS_CREATE":
        return False

    metadata = event.event_metadata or {}

    source_metadata = (
        metadata.get("source_metadata")
        or {}
    )

    image = str(
        source_metadata.get("image")
        or ""
    ).lower()

    command_line = str(
        source_metadata.get("command_line")
        or ""
    ).lower()

    if (
        "powershell.exe" not in image
        and "pwsh.exe" not in image
    ):
        return False

    if not any(
        pattern in command_line
        for pattern in SUSPICIOUS_POWERSHELL_PATTERNS
    ):
        return False

    host = (
        metadata.get("host")
        or "unknown-host"
    )

    finding = upsert_security_finding(
        db,
        finding_type=(
            "SUSPICIOUS_POWERSHELL_EXECUTION"
        ),
        subject=str(host),
        severity=ENDPOINT_001.severity,
        rule_id=ENDPOINT_001.rule_id,
    )

    attach_audit_event_evidence(
        db,
        finding_id=finding.id,
        audit_event_id=event.id,
    )

    return True