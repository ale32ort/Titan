from sqlalchemy import select

from sqlalchemy.orm import Session

from app.domains.security.ai_grounding import GroundingValidationResult
from app.domains.security.ai_triage_models import AITriageRecord


def save_ai_triage_record(
    db: Session,
    *,
    finding_id: str,
    requested_by_user_id: str | None,
    provider: str,
    model: str,
    grounding: GroundingValidationResult,
) -> AITriageRecord:
    output = grounding.output

    record = AITriageRecord(
        finding_id=finding_id,
        requested_by_user_id=requested_by_user_id,
        provider=provider,
        model=model,
        executive_summary=output.executive_summary,
        analyst_assessment=output.analyst_assessment,
        confirmed_facts=output.confirmed_facts,
        hypotheses=output.hypotheses,
        missing_context=output.missing_context,
        recommended_actions=output.recommended_actions,
        confidence=output.confidence,
        compromise_status=output.compromise_status,
        grounding_corrections=grounding.corrections,
    )

    db.add(record)
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
            AITriageRecord.finding_id == finding_id
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