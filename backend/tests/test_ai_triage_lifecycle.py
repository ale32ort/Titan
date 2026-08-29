from sqlalchemy import select
from sqlalchemy.orm import Session
import pytest

from app.domains.security.ai_client import (
    AIClient,
    AIProviderTemporaryError,
)
from app.domains.security.ai_output import (
    AITriageOutput,
)
from app.domains.security.ai_prompt import (
    AIPrompt,
)
from app.domains.security.ai_triage_models import (
    AITriageRecord,
)
from app.domains.security.ai_triage_service import (
    run_ai_triage,
)
from app.domains.security.ai_triage_record_service import (
    AITriageAlreadyRunningError,
    create_ai_triage_record,
)

from conftest import create_test_finding


class SuccessfulAIClient(AIClient):
    model = "test-model"

    def analyze_security_finding(
        self,
        prompt: AIPrompt,
    ) -> AITriageOutput:
        del prompt

        return AITriageOutput(
            executive_summary=(
                "Test AI triage completed."
            ),
            analyst_assessment=(
                "Test evidence was analyzed."
            ),
            confirmed_facts=[
                "A test finding exists.",
            ],
            hypotheses=[
                "Additional investigation may be useful.",
            ],
            missing_context=[
                "Additional telemetry is unavailable.",
            ],
            recommended_actions=[
                "Review the finding.",
            ],
            confidence="medium",
            compromise_status="not_established",
        )


class FailingAIClient(AIClient):
    model = "test-model"

    def analyze_security_finding(
        self,
        prompt: AIPrompt,
    ) -> AITriageOutput:
        del prompt

        raise AIProviderTemporaryError(
            "Test provider unavailable."
        )


def test_successful_ai_triage_is_persisted_as_completed(
    db: Session,
):
    finding = create_test_finding(
        db
    )

    triage_run = run_ai_triage(
        db,
        finding=finding,
        ai_client=SuccessfulAIClient(),
        requested_by_user_id=(
            "test-user-id"
        ),
    )

    record = db.scalar(
        select(AITriageRecord).where(
            AITriageRecord.id
            == triage_run.record.id
        )
    )

    assert record is not None

    assert record.status == "completed"

    assert record.completed_at is not None

    assert record.error_type is None
    assert record.error_message is None

    assert (
        record.executive_summary
        == "Test AI triage completed."
    )

    assert (
        record.compromise_status
        == "not_established"
    )

    assert (
        record.requested_by_user_id
        == "test-user-id"
    )


def test_failed_ai_triage_is_persisted_as_failed(
    db: Session,
):
    finding = create_test_finding(
        db
    )

    try:
        run_ai_triage(
            db,
            finding=finding,
            ai_client=FailingAIClient(),
            requested_by_user_id=(
                "test-user-id"
            ),
        )

    except AIProviderTemporaryError:
        pass

    else:
        raise AssertionError(
            "Expected AIProviderTemporaryError."
        )

    record = db.scalar(
        select(AITriageRecord).where(
            AITriageRecord.finding_id
            == finding.id
        )
    )

    assert record is not None

    assert record.status == "failed"

    assert record.completed_at is not None

    assert (
        record.error_type
        == "AIProviderTemporaryError"
    )

    assert (
        record.error_message
        == "Test provider unavailable."
    )

    assert record.executive_summary is None
    assert record.analyst_assessment is None
    assert record.compromise_status is None

    assert (
        record.requested_by_user_id
        == "test-user-id"
    )

def test_second_running_ai_triage_is_rejected(
    db: Session,
):
    finding = create_test_finding(
        db
    )

    first_record = create_ai_triage_record(
        db,
        finding_id=finding.id,
        requested_by_user_id=(
            "first-test-user"
        ),
        provider="anthropic",
        model="test-model",
    )

    assert first_record.status == "running"

    with pytest.raises(
        AITriageAlreadyRunningError
    ):
        create_ai_triage_record(
            db,
            finding_id=finding.id,
            requested_by_user_id=(
                "second-test-user"
            ),
            provider="anthropic",
            model="test-model",
        )

    records = list(
        db.scalars(
            select(AITriageRecord).where(
                AITriageRecord.finding_id
                == finding.id
            )
        ).all()
    )

    assert len(records) == 1
    assert records[0].id == first_record.id
    assert records[0].status == "running"