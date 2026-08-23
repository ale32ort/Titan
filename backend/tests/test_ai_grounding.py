from datetime import datetime, timedelta, timezone

from app.domains.security.ai_grounding import (
    enforce_ai_grounding,
)
from app.domains.security.ai_output import (
    AITriageOutput,
)
from app.domains.security.rules import AUTH_003
from app.domains.security.triage import (
    TriageContext,
    TriageEvidence,
)
from app.domains.security.triage_analysis import (
    analyze_triage_context,
)


def test_auth_003_grounding_downgrades_confirmed_to_suspected():
    start_time = datetime.now(
        timezone.utc
    )

    evidence = []

    for attempt_number in range(5):
        evidence.append(
            TriageEvidence(
                event_id=(
                    f"failed-{attempt_number}"
                ),
                event_type="LOGIN_FAILED",
                email="grounding@example.com",
                ip_address="10.0.0.40",
                user_agent="pytest-agent",
                result="failure",
                event_metadata=None,
                created_at=(
                    start_time
                    + timedelta(
                        seconds=attempt_number
                    )
                ),
            )
        )

    evidence.append(
        TriageEvidence(
            event_id="success-1",
            event_type="LOGIN_SUCCESS",
            email="grounding@example.com",
            ip_address="10.0.0.40",
            user_agent="pytest-agent",
            result="success",
            event_metadata=None,
            created_at=(
                start_time
                + timedelta(seconds=10)
            ),
        )
    )

    context = TriageContext(
        finding_id="test-finding",
        finding_type=(
            "SUCCESS_AFTER_REPEATED_FAILURES"
        ),
        subject="grounding@example.com",
        severity="high",
        status="open",
        trigger_count=1,
        evidence_count=len(evidence),
        first_seen=start_time,
        last_seen=(
            start_time
            + timedelta(seconds=10)
        ),
        rule=AUTH_003,
        evidence=evidence,
    )

    analysis = analyze_triage_context(
        context
    )

    malicious_ai_output = AITriageOutput(
        executive_summary=(
            "The account was compromised."
        ),
        analyst_assessment=(
            "The successful login confirms "
            "unauthorized access."
        ),
        confirmed_facts=[
            "Repeated authentication failures occurred.",
            "A successful authentication followed.",
        ],
        hypotheses=[],
        missing_context=[
            "Whether the successful login was authorized."
        ],
        recommended_actions=[
            "Validate the successful authentication."
        ],
        confidence="high",
        compromise_status="confirmed",
    )

    result = enforce_ai_grounding(
        context=context,
        analysis=analysis,
        ai_output=malicious_ai_output,
    )

    assert (
        analysis.success_after_failures
        is True
    )

    assert (
        result.output.compromise_status
        == "suspected"
    )

    assert len(result.corrections) == 1

    assert (
        "confirmed"
        in result.corrections[0]
    )

    assert (
        "suspected"
        in result.corrections[0]
    )