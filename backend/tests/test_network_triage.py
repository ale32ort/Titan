from datetime import datetime, timezone

from app.domains.security.ai_grounding import (
    enforce_ai_grounding,
)
from app.domains.security.ai_output import (
    AITriageOutput,
)
from app.domains.security.ai_payload import (
    build_ai_input_payload,
)
from app.domains.security.rules import (
    get_detection_rule,
)
from app.domains.security.triage import (
    TriageContext,
    TriageEvidence,
)
from app.domains.security.triage_analysis import (
    analyze_triage_context,
)
from app.domains.security.triage_result import (
    build_deterministic_triage_result,
)


def build_network_context() -> TriageContext:
    now = datetime.now(
        timezone.utc
    )

    evidence = TriageEvidence(
        event_id="event-1",
        event_type=(
            "SENSOR_SURICATA_ALERT"
        ),
        email=None,
        ip_address="10.0.0.143",
        user_agent=None,
        result="observed",
        event_metadata={
            "source": "suricata",
            "sensor_event_type": "alert",
            "host": "soclab",
            "source_ip": "10.0.0.143",
            "destination_ip": "10.0.0.13",
            "severity": "3",
            "message": (
                "TITAN LAB Nmap "
                "Port Scan Detected"
            ),
            "observed_at": now.isoformat(),
            "source_metadata": {
                "signature": (
                    "TITAN LAB Nmap "
                    "Port Scan Detected"
                ),
                "signature_id": 9000001,
                "category": (
                    "Detection of a Network Scan"
                ),
                "action": "allowed",
                "protocol": "TCP",
                "source_port": 38519,
                "destination_port": 72,
                "flow_id": 123456,
            },
        },
        created_at=now,
    )

    return TriageContext(
        finding_id="finding-1",
        finding_type=(
            "NETWORK_RECONNAISSANCE"
        ),
        subject="10.0.0.143",
        severity="medium",
        status="open",
        trigger_count=1,
        evidence_count=1,
        first_seen=now,
        last_seen=now,
        rule=get_detection_rule(
            "NET-001"
        ),
        evidence=[evidence],
    )


def test_network_triage_analysis():
    context = build_network_context()

    analysis = analyze_triage_context(
        context
    )

    assert analysis.sensor_alert_count == 1

    assert (
        analysis.network_source_ip_count
        == 1
    )

    assert (
        analysis.network_destination_ip_count
        == 1
    )

    assert (
        analysis.network_destination_port_count
        == 1
    )

    assert (
        analysis.network_protocol_count
        == 1
    )

    assert (
        analysis.suricata_signature_count
        == 1
    )

    assert (
        analysis.network_recon_evidence_present
        is True
    )


def test_network_triage_result():
    context = build_network_context()

    analysis = analyze_triage_context(
        context
    )

    result = (
        build_deterministic_triage_result(
            context,
            analysis,
        )
    )

    assert (
        "network reconnaissance"
        in result.summary.lower()
    )

    assert (
        "does not establish"
        in result.assessment.lower()
    )

    assert (
        result.mitre_technique_id
        == "T1046"
    )


def test_network_ai_payload_contains_safe_sensor_data():
    context = build_network_context()

    analysis = analyze_triage_context(
        context
    )

    result = (
        build_deterministic_triage_result(
            context,
            analysis,
        )
    )

    payload = build_ai_input_payload(
        context,
        analysis,
        result,
    )

    sensor = payload.evidence[0][
        "sensor"
    ]

    assert (
        sensor["source_ip"]
        == "10.0.0.143"
    )

    assert (
        sensor["destination_ip"]
        == "10.0.0.13"
    )

    assert (
        sensor["signature_id"]
        == 9000001
    )

    assert (
        "Nmap"
        in sensor["signature"]
    )


def test_network_grounding_prevents_false_compromise():
    context = build_network_context()

    analysis = analyze_triage_context(
        context
    )

    ai_output = AITriageOutput(
        executive_summary=(
            "Network reconnaissance was detected."
        ),
        analyst_assessment=(
            "The activity appears consistent "
            "with a port scan."
        ),
        confirmed_facts=[
            "Suricata detected scanning activity.",
        ],
        hypotheses=[
            "The source may be performing "
            "network discovery.",
        ],
        missing_context=[
            "Authorization status is unknown.",
        ],
        recommended_actions=[
            "Validate the source IP.",
        ],
        confidence="high",
        compromise_status="confirmed",
    )

    grounded = enforce_ai_grounding(
        context=context,
        analysis=analysis,
        ai_output=ai_output,
    )

    assert (
        grounded.output.compromise_status
        == "not_established"
    )

    assert len(
        grounded.corrections
    ) == 1