from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.domains.security.ai_grounding import (
    GroundingValidationResult,
)
from app.domains.security.ai_triage_models import (
    AITriageRecord,
)

class AITriageAlreadyRunningError(
    RuntimeError
):
    """
    Raised when an AI investigation is
    already running for the same finding.
    """

def create_ai_triage_record(
    db: Session,
    *,
    finding_id: str,
    requested_by_user_id: str | None,
    provider: str,
    model: str,
) -> AITriageRecord:
    record = AITriageRecord(
        finding_id=finding_id,
        requested_by_user_id=(
            requested_by_user_id
        ),
        provider=provider,
        model=model,
        status="running",
    )

    db.add(record)

    try:
        db.commit()

    except IntegrityError:
        db.rollback()

        running_record = db.scalar(
            select(AITriageRecord).where(
                AITriageRecord.finding_id
                == finding_id,
                AITriageRecord.status
                == "running",
            )
        )

        if running_record is not None:
            raise (
                AITriageAlreadyRunningError(
                    "An AI investigation is "
                    "already running for this "
                    "finding."
                )
            )

        raise

    db.refresh(record)

    return record

def complete_ai_triage_record(
    db: Session,
    *,
    record: AITriageRecord,
    grounding: GroundingValidationResult,
) -> AITriageRecord:
    output = grounding.output

    record.status = "completed"
    record.error_type = None
    record.error_message = None

    record.executive_summary = (
        output.executive_summary
    )
    record.analyst_assessment = (
        output.analyst_assessment
    )
    record.confirmed_facts = (
        output.confirmed_facts
    )
    record.hypotheses = (
        output.hypotheses
    )
    record.missing_context = (
        output.missing_context
    )
    record.recommended_actions = (
        output.recommended_actions
    )
    record.confidence = (
        output.confidence
    )
    record.compromise_status = (
        output.compromise_status
    )
    record.grounding_corrections = (
        grounding.corrections
    )
    record.completed_at = datetime.now(
        timezone.utc
    )

    db.commit()
    db.refresh(record)

    return record


def fail_ai_triage_record(
    db: Session,
    *,
    record: AITriageRecord,
    error_type: str,
    error_message: str,
) -> AITriageRecord:
    record.status = "failed"
    record.error_type = error_type
    record.error_message = error_message
    record.completed_at = datetime.now(
        timezone.utc
    )

    db.commit()
    db.refresh(record)

    return record


def get_ai_triage_records_for_finding(
    db: Session,
    *,
    finding_id: str,
) -> list[AITriageRecord]:
    statement = (
        select(AITriageRecord)
        .where(
            AITriageRecord.finding_id
            == finding_id
        )
        .order_by(
            AITriageRecord.created_at.desc()
        )
    )

    return list(
        db.scalars(statement).all()
    )


def get_ai_triage_record(
    db: Session,
    *,
    triage_run_id: str,
) -> AITriageRecord | None:
    return db.get(
        AITriageRecord,
        triage_run_id,
    )