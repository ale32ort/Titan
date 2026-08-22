from dataclasses import dataclass

from app.domains.security.triage import TriageContext


@dataclass(frozen=True)
class TriageAnalysis:
    failed_login_count: int
    successful_login_count: int
    success_after_failures: bool
    distinct_target_account_count: int
    unique_ip_count: int
    unique_user_agent_count: int
    duration_seconds: float
    threshold: int | None
    threshold_metric: str | None
    threshold_observed_value: int | None
    threshold_exceeded_by: int | None


def analyze_triage_context(
    context: TriageContext,
) -> TriageAnalysis:
    """
    Perform deterministic calculations over the evidence
    attached to a security finding.

    The meaning of the rule threshold is rule-specific:

    AUTH-001:
        threshold applies to failed login count.

    AUTH-002:
        threshold applies to distinct targeted accounts.

    AUTH-003:
        threshold applies to failed login count, while also
        confirming whether a successful login occurred after
        the failed attempts.
    """

    failed_login_events = [
        event
        for event in context.evidence
        if event.event_type == "LOGIN_FAILED"
    ]

    successful_login_events = [
        event
        for event in context.evidence
        if event.event_type == "LOGIN_SUCCESS"
    ]

    failed_login_count = len(
        failed_login_events
    )

    successful_login_count = len(
        successful_login_events
    )

    success_after_failures = False

    if (
        failed_login_events
        and successful_login_events
    ):
        latest_failed_login = max(
            event.created_at
            for event in failed_login_events
        )

        earliest_successful_login = min(
            event.created_at
            for event in successful_login_events
        )

        success_after_failures = (
            earliest_successful_login
            > latest_failed_login
        )

    targeted_accounts = {
        event.email
        for event in failed_login_events
        if event.email
    }

    unique_ips = {
        event.ip_address
        for event in context.evidence
        if event.ip_address
    }

    unique_user_agents = {
        event.user_agent
        for event in context.evidence
        if event.user_agent
    }

    if context.evidence:
        first_event = min(
            event.created_at
            for event in context.evidence
        )

        last_event = max(
            event.created_at
            for event in context.evidence
        )

        duration_seconds = (
            last_event - first_event
        ).total_seconds()

    else:
        duration_seconds = 0.0

    threshold = (
        context.rule.threshold
        if context.rule
        else None
    )

    threshold_metric: str | None = None
    threshold_observed_value: int | None = None

    if context.rule:
        if context.rule.rule_id == "AUTH-001":
            threshold_metric = (
                "failed_login_count"
            )

            threshold_observed_value = (
                failed_login_count
            )

        elif context.rule.rule_id == "AUTH-002":
            threshold_metric = (
                "distinct_target_account_count"
            )

            threshold_observed_value = len(
                targeted_accounts
            )

        elif context.rule.rule_id == "AUTH-003":
            threshold_metric = (
                "failed_login_count"
            )

            threshold_observed_value = (
                failed_login_count
            )

    threshold_exceeded_by = (
        threshold_observed_value - threshold
        if (
            threshold is not None
            and threshold_observed_value is not None
        )
        else None
    )

    return TriageAnalysis(
        failed_login_count=failed_login_count,
        successful_login_count=successful_login_count,
        success_after_failures=success_after_failures,
        distinct_target_account_count=len(
            targeted_accounts
        ),
        unique_ip_count=len(
            unique_ips
        ),
        unique_user_agent_count=len(
            unique_user_agents
        ),
        duration_seconds=duration_seconds,
        threshold=threshold,
        threshold_metric=threshold_metric,
        threshold_observed_value=(
            threshold_observed_value
        ),
        threshold_exceeded_by=(
            threshold_exceeded_by
        ),
    )