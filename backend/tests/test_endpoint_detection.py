from app.domains.security.detections.endpoint import (
    detect_suspicious_powershell,
)
from app.domains.security.evidence_service import (
    get_finding_audit_events,
)
from app.domains.security.findings import (
    SecurityFinding,
)
from app.domains.security.models import AuditEvent


def test_endpoint_001_ignores_non_sysmon_event(
    db,
):
    event = AuditEvent(
        event_type="SENSOR_SURICATA_ALERT",
        result="observed",
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = detect_suspicious_powershell(
        db,
        event_id=event.id,
    )

    assert detected is False


def test_endpoint_001_ignores_normal_powershell(
    db,
):
    event = AuditEvent(
        event_type="SENSOR_SYSMON_PROCESS_CREATE",
        result="observed",
        event_metadata={
            "host": "workstation-01",
            "source_metadata": {
                "image": (
                    "C:\\Windows\\System32\\"
                    "WindowsPowerShell\\v1.0\\"
                    "powershell.exe"
                ),
                "command_line": (
                    "powershell.exe Get-Process"
                ),
            },
        },
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = detect_suspicious_powershell(
        db,
        event_id=event.id,
    )

    assert detected is False


def test_endpoint_001_creates_finding_and_exact_evidence(
    db,
):
    event = AuditEvent(
        event_type="SENSOR_SYSMON_PROCESS_CREATE",
        result="observed",
        event_metadata={
            "host": "workstation-01",
            "source_metadata": {
                "image": (
                    "C:\\Windows\\System32\\"
                    "WindowsPowerShell\\v1.0\\"
                    "powershell.exe"
                ),
                "command_line": (
                    "powershell.exe -EncodedCommand "
                    "SQBFAFgAIAAoACcAdABlAHMAdAAnACkA"
                ),
            },
        },
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = detect_suspicious_powershell(
        db,
        event_id=event.id,
    )

    assert detected is True

    finding = db.query(
        SecurityFinding
    ).filter(
        SecurityFinding.rule_id
        == "ENDPOINT-001"
    ).one()

    assert finding.finding_type == (
        "SUSPICIOUS_POWERSHELL_EXECUTION"
    )

    assert finding.subject == (
        "workstation-01"
    )

    assert finding.severity == "high"

    evidence = get_finding_audit_events(
        db,
        finding_id=finding.id,
    )

    assert len(evidence) == 1
    assert evidence[0].id == event.id