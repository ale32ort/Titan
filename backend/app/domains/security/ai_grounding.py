from dataclasses import dataclass

from app.domains.security.ai_output import (
    AITriageOutput,
)
from app.domains.security.triage import (
    TriageContext,
)
from app.domains.security.triage_analysis import (
    TriageAnalysis,
)


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
    Apply deterministic policy constraints to
    AI-generated triage output.

    AI may interpret evidence, but Titan retains
    authority over evidence-backed security
    invariants.
    """

    corrections: list[str] = []

    compromise_status = (
        ai_output.compromise_status
    )

    has_successful_login_evidence = (
        analysis.successful_login_count > 0
    )

    # ---------------------------------------------------------
    # AUTH-001
    # ---------------------------------------------------------

    if (
        context.finding_type
        == "AUTH_BRUTE_FORCE_SUSPECTED"
        and not has_successful_login_evidence
        and compromise_status
        != "not_established"
    ):
        compromise_status = (
            "not_established"
        )

        corrections.append(
            "Compromise status changed to "
            "'not_established' because the supplied "
            "evidence contains failed authentication "
            "attempts but no successful authentication "
            "or other evidence establishing account "
            "compromise."
        )

    # ---------------------------------------------------------
    # AUTH-002
    # ---------------------------------------------------------

    if (
        context.finding_type
        == "PASSWORD_SPRAY_SUSPECTED"
        and not has_successful_login_evidence
        and compromise_status
        != "not_established"
    ):
        compromise_status = (
            "not_established"
        )

        corrections.append(
            "Compromise status changed to "
            "'not_established' because the "
            "password-spray evidence contains no "
            "successful authentication or other "
            "evidence establishing account compromise."
        )

    # ---------------------------------------------------------
    # AUTH-003
    # ---------------------------------------------------------

    if (
        context.finding_type
        == "SUCCESS_AFTER_REPEATED_FAILURES"
        and analysis.success_after_failures
        and compromise_status
        == "confirmed"
    ):
        compromise_status = "suspected"

        corrections.append(
            "Compromise status changed from "
            "'confirmed' to 'suspected' because the "
            "evidence establishes a successful login "
            "after repeated failures, but does not "
            "establish that the successful "
            "authentication was unauthorized."
        )

    if (
        context.finding_type
        == "SUCCESS_AFTER_REPEATED_FAILURES"
        and not analysis.success_after_failures
        and compromise_status
        != "not_established"
    ):
        compromise_status = (
            "not_established"
        )

        corrections.append(
            "Compromise status changed to "
            "'not_established' because Titan could not "
            "deterministically confirm a successful "
            "authentication occurred after the failed "
            "attempts."
        )

    # ---------------------------------------------------------
    # NET-001
    #
    # Reconnaissance can be confirmed as activity without
    # establishing host compromise.
    # ---------------------------------------------------------

    if (
        context.finding_type
        == "NETWORK_RECONNAISSANCE"
        and compromise_status
        != "not_established"
    ):
        compromise_status = (
            "not_established"
        )

        corrections.append(
            "Compromise status changed to "
            "'not_established' because the supplied "
            "network evidence establishes "
            "reconnaissance or scanning activity, but "
            "does not establish successful exploitation "
            "or compromise of the targeted system."
        )

            # ---------------------------------------------------------
    # ENDPOINT-001
    #
    # Suspicious PowerShell execution establishes that a
    # suspicious execution pattern occurred. It does not,
    # by itself, prove successful malicious execution or
    # compromise of the endpoint.
    # ---------------------------------------------------------

    if (
        context.finding_type
        == "SUSPICIOUS_POWERSHELL_EXECUTION"
        and compromise_status
        != "not_established"
    ):
        compromise_status = (
            "not_established"
        )

        corrections.append(
            "Compromise status changed to "
            "'not_established' because the supplied "
            "Sysmon evidence establishes suspicious "
            "PowerShell execution, but does not by "
            "itself establish successful malicious "
            "execution or compromise of the endpoint."
        )

    grounded_output = (
        ai_output.model_copy(
            update={
                "compromise_status":
                    compromise_status,
            }
        )
    )

    return GroundingValidationResult(
        output=grounded_output,
        corrections=corrections,
    )