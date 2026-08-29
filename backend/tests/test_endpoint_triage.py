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


def build_endpoint_context() -> TriageContext:
    now = datetime.now(
        timezone.utc
    )

    evidence = TriageEvidence(
        event_id="event-endpoint-1",
        event_type=(
            "SENSOR_SYSMON_PROCESS_CREATE"
        ),
        email=None,
        ip_address=None,
        user_agent=None,
        result="observed",
        event_metadata={
            "source": "sysmon",
            "sensor_event_type": (
                "process_create"
            ),
            "host": "tito",
            "source_ip": None,
            "destination_ip": None,
            "severity": None,
            "message": (
                "Process creation: "
                "powershell.exe"
            ),
            "observed_at": (
                now.isoformat()
            ),
            "source_metadata": {
                "image": (
                    "C:\\Windows\\System32\\"
                    "WindowsPowerShell\\v1.0\\"
                    "powershell.exe"
                ),
                "command_line": (
                    "powershell.exe "
                    "-EncodedCommand "
                    "VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA"
                ),
                "parent_image": (
                    "C:\\Windows\\System32\\"
                    "cmd.exe"
                ),
                "parent_command_line": (
                    "cmd.exe"
                ),
                "user": "ale32",
                "user_domain": "TITO",
                "process_id": 1234,
                "process_guid": (
                    "{TEST-PROCESS-GUID}"
                ),
                "parent_process_id": 4321,
                "parent_process_guid": (
                    "{TEST-PARENT-GUID}"
                ),
                "record_id": "9999",
                "elastic_document_id": (
                    "elastic-test-id"
                ),

                # This field proves arbitrary metadata
                # is not forwarded into the AI payload.
                "internal_secret": (
                    "do-not-send-to-ai"
                ),
            },
        },
        created_at=now,
    )

    return TriageContext(
        finding_id="finding-endpoint-1",
        finding_type=(
            "SUSPICIOUS_POWERSHELL_EXECUTION"
        ),
        subject="tito",
        severity="high",
        status="open",
        trigger_count=1,
        evidence_count=1,
        first_seen=now,
        last_seen=now,
        rule=get_detection_rule(
            "ENDPOINT-001"
        ),
        evidence=[evidence],
    )


def test_endpoint_triage_analysis():
    context = build_endpoint_context()

    analysis = analyze_triage_context(
        context
    )

    assert (
        analysis.sysmon_process_create_count
        == 1
    )

    assert (
        analysis.powershell_process_count
        == 1
    )

    assert (
        analysis.suspicious_powershell_event_count
        == 1
    )

    assert (
        analysis.endpoint_host_count
        == 1
    )

    assert (
        analysis.suspicious_powershell_pattern_present
        is True
    )


def test_endpoint_triage_result():
    context = build_endpoint_context()

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
        "powershell"
        in result.summary.lower()
    )

    assert (
        "does not"
        in result.assessment.lower()
    )

    assert (
        result.mitre_technique_id
        == "T1059.001"
    )


def test_endpoint_ai_payload_contains_safe_sysmon_data():
    context = build_endpoint_context()

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
        sensor["host"]
        == "tito"
    )

    assert (
        "powershell.exe"
        in sensor["image"].lower()
    )

    assert (
        "-EncodedCommand"
        in sensor["command_line"]
    )

    assert (
        sensor["process_id"]
        == 1234
    )

    assert (
        "internal_secret"
        not in sensor
    )


def test_endpoint_grounding_prevents_false_compromise():
    context = build_endpoint_context()

    analysis = analyze_triage_context(
        context
    )

    ai_output = AITriageOutput(
        executive_summary=(
            "Suspicious PowerShell execution "
            "was observed."
        ),
        analyst_assessment=(
            "The command line matched a "
            "configured suspicious pattern."
        ),
        confirmed_facts=[
            (
                "Sysmon recorded a PowerShell "
                "process creation event."
            ),
        ],
        hypotheses=[
            (
                "The activity may require "
                "additional investigation."
            ),
        ],
        missing_context=[
            (
                "Authorization status is unknown."
            ),
        ],
        recommended_actions=[
            (
                "Validate the PowerShell command."
            ),
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

    assert (
        len(grounded.corrections)
        == 1
    )