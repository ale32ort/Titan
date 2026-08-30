from datetime import datetime, timezone

from app.domains.security.schemas import AITriageRunPublic


def test_failed_ai_triage_run_serializes_with_null_output_fields():
    run = {
        "id": "triage-test-1",
        "finding_id": "finding-test-1",
        "requested_by_user_id": None,
        "provider": "anthropic",
        "model": "claude-sonnet-5",
        "status": "failed",
        "error_type": "AIProviderTimeoutError",
        "error_message": "Provider request timed out.",
        "executive_summary": None,
        "analyst_assessment": None,
        "confirmed_facts": None,
        "hypotheses": None,
        "missing_context": None,
        "recommended_actions": None,
        "confidence": None,
        "compromise_status": None,
        "grounding_corrections": None,
        "created_at": datetime.now(timezone.utc),
        "completed_at": datetime.now(timezone.utc),
    }

    result = AITriageRunPublic.model_validate(run)

    assert result.status == "failed"
    assert result.error_type == "AIProviderTimeoutError"
    assert result.executive_summary is None
    assert result.confidence is None
    assert result.compromise_status is None