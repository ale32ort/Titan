from app.domains.security.detections.network import (
    detect_network_reconnaissance,
)
from app.domains.security.evidence_service import (
    get_finding_audit_events,
)
from app.domains.security.findings import (
    SecurityFinding,
)
from app.domains.security.models import (
    AuditEvent,
)


def test_net_001_ignores_non_suricata_event(
    db,
):
    event = AuditEvent(
        event_type="LOGIN_FAILED",
        result="failure",
        ip_address="192.0.2.10",
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = (
        detect_network_reconnaissance(
            db,
            event_id=event.id,
        )
    )

    assert detected is False


def test_net_001_ignores_non_recon_suricata_alert(
    db,
):
    event = AuditEvent(
        event_type="SENSOR_SURICATA_ALERT",
        result="observed",
        ip_address="192.0.2.20",
        event_metadata={
            "message": "TLS certificate anomaly",
            "source_metadata": {},
        },
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = (
        detect_network_reconnaissance(
            db,
            event_id=event.id,
        )
    )

    assert detected is False


def test_net_001_creates_finding_and_exact_evidence(
    db,
):
    event = AuditEvent(
        event_type="SENSOR_SURICATA_ALERT",
        result="observed",
        ip_address="192.0.2.50",
        event_metadata={
            "source_ip": "192.0.2.50",
            "message": (
                "Possible Nmap port scan detected"
            ),
            "source_metadata": {
                "signature_id": 2001219,
                "protocol": "TCP",
            },
        },
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detected = (
        detect_network_reconnaissance(
            db,
            event_id=event.id,
        )
    )

    assert detected is True

    finding = db.query(
        SecurityFinding
    ).filter(
        SecurityFinding.rule_id
        == "NET-001"
    ).one()

    assert finding.finding_type == (
        "NETWORK_RECONNAISSANCE"
    )

    assert finding.subject == (
        "192.0.2.50"
    )

    assert finding.severity == "medium"

    evidence = (
        get_finding_audit_events(
            db,
            finding_id=finding.id,
        )
    )

    assert len(evidence) == 1
    assert evidence[0].id == event.id