from dataclasses import dataclass

from app.domains.security.triage import TriageContext
from app.domains.security.triage_analysis import TriageAnalysis


@dataclass(frozen=True)
class TriageResult:
    summary: str
    risk_level: str
    assessment: str
    recommended_actions: list[str]
    mitre_tactic: str | None
    mitre_technique_id: str | None
    mitre_technique_name: str | None


def build_deterministic_triage_result(
    context: TriageContext,
    analysis: TriageAnalysis,
) -> TriageResult:
    """Build an analyst-friendly triage result from deterministic facts."""

    if context.rule and context.rule.rule_id == "AUTH-002":
        summary = (
            f"{analysis.failed_login_count} failed login attempts were observed "
            f"from {context.subject}, targeting "
            f"{analysis.distinct_target_account_count} distinct accounts over "
            f"{analysis.duration_seconds:.2f} seconds."
        )

    else:
        summary = (
            f"{analysis.failed_login_count} failed login attempts were observed "
            f"against {context.subject} over "
            f"{analysis.duration_seconds:.2f} seconds."
        )

    if (
        context.rule
        and analysis.threshold is not None
        and analysis.threshold_observed_value is not None
    ):
        if analysis.threshold_metric == "failed_login_count":
            threshold_description = (
                f"{analysis.threshold_observed_value} failed login attempts"
            )

        elif (
            analysis.threshold_metric
            == "distinct_target_account_count"
        ):
            threshold_description = (
                f"{analysis.threshold_observed_value} distinct targeted accounts"
            )

        else:
            threshold_description = (
                f"an observed value of "
                f"{analysis.threshold_observed_value}"
            )

        assessment = (
            f"The activity triggered {context.rule.rule_id} "
            f"({context.rule.name}) because "
            f"{threshold_description} met or exceeded the configured "
            f"threshold of {analysis.threshold} within "
            f"{context.rule.window_minutes} minutes."
        )

    else:
        assessment = (
            "The finding contains suspicious authentication activity, "
            "but complete rule metadata is unavailable."
        )

    if context.rule and context.rule.rule_id == "AUTH-002":
        recommended_actions = [
            "Review the source IP address and determine whether it is expected.",
            "Verify whether the targeted email addresses correspond to real accounts.",
            "Review successful logins for the targeted accounts around the same time.",
            "Review additional authentication activity from the same source IP.",
            "Confirm whether the activity originated from testing, automation, or an approved security tool.",
            "Consider rate limiting or additional authentication protections if the activity continues.",
        ]

    else:
        recommended_actions = [
            "Review the source IP address and determine whether it is expected.",
            "Review successful logins for the affected account around the same time.",
            "Confirm whether the account owner recognizes the authentication activity.",
            "Review additional authentication activity from the same source.",
            "Consider rate limiting or additional account protections if the activity continues.",
        ]

    return TriageResult(
        summary=summary,
        risk_level=context.severity,
        assessment=assessment,
        recommended_actions=recommended_actions,
        mitre_tactic=(
            context.rule.mitre_tactic
            if context.rule
            else None
        ),
        mitre_technique_id=(
            context.rule.mitre_technique_id
            if context.rule
            else None
        ),
        mitre_technique_name=(
            context.rule.mitre_technique_name
            if context.rule
            else None
        ),
    )