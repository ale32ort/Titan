from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.domains.security.ai_client import (
    AIClient,
    AIProviderError,
)
from app.domains.security.ai_grounding import (
    GroundingValidationResult,
    enforce_ai_grounding,
)
from app.domains.security.ai_payload import (
    build_ai_input_payload,
)
from app.domains.security.ai_prompt import (
    build_ai_prompt,
)
from app.domains.security.ai_triage_models import (
    AITriageRecord,
)
from app.domains.security.ai_triage_record_service import (
    complete_ai_triage_record,
    create_ai_triage_record,
    fail_ai_triage_record,
)
from app.domains.security.findings import (
    SecurityFinding,
)
from app.domains.security.triage import (
    TriageContext,
    build_triage_context,
)
from app.domains.security.triage_analysis import (
    TriageAnalysis,
    analyze_triage_context,
)
from app.domains.security.triage_result import (
    TriageResult,
    build_deterministic_triage_result,
)


@dataclass(frozen=True)
class AITriageRun:
    context: TriageContext
    analysis: TriageAnalysis
    deterministic_result: TriageResult
    grounding: GroundingValidationResult
    record: AITriageRecord


def run_ai_triage(
    db: Session,
    *,
    finding: SecurityFinding,
    ai_client: AIClient,
    requested_by_user_id: str | None = None,
) -> AITriageRun:
    """
    Run Titan's complete AI-assisted
    security triage pipeline.

    The triage run is persisted before
    contacting the external AI provider so
    failures remain visible to analysts.
    """

    context = build_triage_context(
        db,
        finding=finding,
    )

    analysis = analyze_triage_context(
        context
    )

    deterministic_result = (
        build_deterministic_triage_result(
            context,
            analysis,
        )
    )

    payload = build_ai_input_payload(
        context,
        analysis,
        deterministic_result,
    )

    prompt = build_ai_prompt(
        payload
    )

    record = create_ai_triage_record(
        db,
        finding_id=finding.id,
        requested_by_user_id=(
            requested_by_user_id
        ),
        provider="anthropic",
        model=getattr(
            ai_client,
            "model",
            "unknown",
        ),
    )

    try:
        ai_output = (
            ai_client.analyze_security_finding(
                prompt
            )
        )

        grounding = enforce_ai_grounding(
            context=context,
            analysis=analysis,
            ai_output=ai_output,
        )

        record = (
            complete_ai_triage_record(
                db,
                record=record,
                grounding=grounding,
            )
        )

    except AIProviderError as exc:
        fail_ai_triage_record(
            db,
            record=record,
            error_type=(
                type(exc).__name__
            ),
            error_message=str(exc),
        )

        raise

    except Exception as exc:
        fail_ai_triage_record(
            db,
            record=record,
            error_type=(
                type(exc).__name__
            ),
            error_message=(
                "Unexpected AI triage failure."
            ),
        )

        raise

    return AITriageRun(
        context=context,
        analysis=analysis,
        deterministic_result=(
            deterministic_result
        ),
        grounding=grounding,
        record=record,
    )

