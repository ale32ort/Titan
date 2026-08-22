from dataclasses import dataclass

from app.domains.security.ai_output import AITriageOutput
from app.domains.security.triage import TriageContext
from app.domains.security.triage_analysis import TriageAnalysis


@dataclass(frozen=True)
class GroundingValidationResult:
    output: AITriageOutput
    corrections: list[str]


def enforce_ai_grounding(
    *,
    context: TriageContext,
    analysis: TriageAnalysis,
    ai_output: AITriageOutput,
) -> GroundingValidationResult:
    """
    Apply deterministic policy constraints to AI-generated triage output.

    The AI may interpret evidence, but Titan retains authority over
    evidence-backed security invariants.
    """

    corrections: list[str] = []

    compromise_status = ai_output.compromise_status

    has_successful_login_evidence = (
        analysis.successful_login_count > 0
    )

    # ---------------------------------------------------------
    # AUTH-001 — repeated failed logins against one account
    #
    # Failed authentication attempts alone do not establish
    # account compromise.
    # ---------------------------------------------------------

    if (
        context.finding_type == "AUTH_BRUTE_FORCE_SUSPECTED"
        and not has_successful_login_evidence
        and compromise_status != "not_established"
    ):
        compromise_status = "not_established"

        corrections.append(
            "Compromise status changed to 'not_established' because "
            "the supplied evidence contains failed authentication "
            "attempts but no successful authentication or other "
            "evidence establishing account compromise."
        )

    # ---------------------------------------------------------
    # AUTH-002 — password spray
    #
    # A spray consisting only of failed authentications does
    # not establish compromise, regardless of the number of
    # accounts targeted.
    # ---------------------------------------------------------

    if (
        context.finding_type == "PASSWORD_SPRAY_SUSPECTED"
        and not has_successful_login_evidence
        and compromise_status != "not_established"
    ):
        compromise_status = "not_established"

        corrections.append(
            "Compromise status changed to 'not_established' because "
            "the password-spray evidence contains no successful "
            "authentication or other evidence establishing account "
            "compromise."
        )

    # ---------------------------------------------------------
    # AUTH-003 — successful login after repeated failures
    #
    # A successful login following repeated failures can justify
    # suspicion, but does not by itself prove the login was
    # unauthorized.
    #
    # Therefore:
    #   not_established -> allowed
    #   suspected       -> allowed
    #   confirmed       -> downgraded to suspected
    # ---------------------------------------------------------

    if (
        context.finding_type == "SUCCESS_AFTER_REPEATED_FAILURES"
        and analysis.success_after_failures
        and compromise_status == "confirmed"
    ):
        compromise_status = "suspected"

        corrections.append(
            "Compromise status changed from 'confirmed' to 'suspected' "
            "because the evidence establishes a successful login after "
            "repeated failures, but does not establish that the "
            "successful authentication was unauthorized."
        )

    # Defensive fallback:
    #
    # If an AUTH-003 finding somehow lacks deterministic evidence
    # that a success actually occurred after the failures, Titan
    # should not allow the AI to elevate compromise.
    if (
        context.finding_type == "SUCCESS_AFTER_REPEATED_FAILURES"
        and not analysis.success_after_failures
        and compromise_status != "not_established"
    ):
        compromise_status = "not_established"

        corrections.append(
            "Compromise status changed to 'not_established' because "
            "Titan could not deterministically confirm a successful "
            "authentication occurred after the failed attempts."
        )

    grounded_output = ai_output.model_copy(
        update={
            "compromise_status": compromise_status,
        }
    )

    return GroundingValidationResult(
        output=grounded_output,
        corrections=corrections,
    )