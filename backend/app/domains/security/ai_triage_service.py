from dataclasses import dataclass
from app.domains.security.ai_triage_models import AITriageRecord
from app.domains.security.ai_triage_record_service import save_ai_triage_record
from sqlalchemy.orm import Session

from app.domains.security.ai_grounding import (
    GroundingValidationResult,
    enforce_ai_grounding,
)
from app.domains.security.ai_payload import build_ai_input_payload
from app.domains.security.ai_prompt import build_ai_prompt
from app.domains.security.claude_client import AIClient
from app.domains.security.findings import SecurityFinding
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
    Run Titan's complete AI-assisted security triage pipeline.
    """

    context = build_triage_context(
        db,
        finding=finding,
    )

    analysis = analyze_triage_context(
        context
    )

    deterministic_result = build_deterministic_triage_result(
        context,
        analysis,
    )

    payload = build_ai_input_payload(
        context,
        analysis,
        deterministic_result,
    )

    prompt = build_ai_prompt(
        payload
    )

    ai_output = ai_client.analyze_security_finding(
        prompt
    )

    grounding = enforce_ai_grounding(
        context=context,
        analysis=analysis,
        ai_output=ai_output,
    )
    
    record = save_ai_triage_record(
    db,
    finding_id=finding.id,
    requested_by_user_id=requested_by_user_id,
    provider="anthropic",
    model=getattr(ai_client, "model", "unknown"),
    grounding=grounding,
)

    return AITriageRun(
        context=context,
        analysis=analysis,
        deterministic_result=deterministic_result,
        grounding=grounding,
        record=record,
    )

