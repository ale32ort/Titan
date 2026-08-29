from dataclasses import dataclass

from app.domains.security.triage import (
    TriageContext,
)
from app.domains.security.triage_analysis import (
    TriageAnalysis,
)


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
    """
    Build an analyst-friendly triage result
    entirely from deterministic evidence.
    """

    rule_id = (
        context.rule.rule_id
        if context.rule
        else None
    )

        # ---------------------------------------------------------
    # ENDPOINT-001
    # ---------------------------------------------------------

    if rule_id == "ENDPOINT-001":
        summary = (
            f"{analysis.sysmon_process_create_count} "
            f"Sysmon process creation event(s) were "
            f"attached to this finding for "
            f"{context.subject}. "
            f"{analysis.suspicious_powershell_event_count} "
            f"PowerShell event(s) contained a suspicious "
            f"execution pattern."
        )

        if (
            analysis.suspicious_powershell_pattern_present
        ):
            assessment = (
                f"The attached Sysmon evidence contains "
                f"a PowerShell process whose command line "
                f"matched a suspicious execution pattern "
                f"and triggered {context.rule.rule_id} "
                f"({context.rule.name}). "
                f"This establishes suspicious PowerShell "
                f"execution activity, but does not by "
                f"itself establish successful malicious "
                f"execution or host compromise."
            )

        else:
            assessment = (
                f"The finding is associated with "
                f"{context.rule.rule_id} "
                f"({context.rule.name}), but Titan could "
                f"not independently confirm a configured "
                f"suspicious PowerShell pattern in the "
                f"attached Sysmon evidence."
            )

        recommended_actions = [
            (
                "Review the complete PowerShell command "
                "line and determine whether it was "
                "authorized."
            ),
            (
                "Review the parent process and process "
                "tree to determine what launched "
                "PowerShell."
            ),
            (
                "Validate the user account and host "
                "associated with the execution."
            ),
            (
                "Review surrounding Sysmon events for "
                "child processes, file creation, registry "
                "changes, or other follow-on activity."
            ),
            (
                "Review relevant network telemetry for "
                "connections associated with the "
                "PowerShell process."
            ),
            (
                "Escalate if the command is unauthorized "
                "or corroborating malicious activity is "
                "identified."
            ),
        ]

    # ---------------------------------------------------------
    # NET-001
    # ---------------------------------------------------------

    elif rule_id == "NET-001":

    # ---------------------------------------------------------
    # NET-001
    # ---------------------------------------------------------

        if rule_id == "NET-001":
         summary = (
            f"{analysis.sensor_alert_count} "
            f"Suricata alert(s) associated with "
            f"network reconnaissance were observed "
            f"from {context.subject}, involving "
            f"{analysis.network_destination_ip_count} "
            f"destination IP(s) and "
            f"{analysis.network_destination_port_count} "
            f"observed destination port(s)."
        )

        if (
            analysis.network_recon_evidence_present
        ):
            assessment = (
                f"The evidence attached to this finding "
                f"contains Suricata reconnaissance or "
                f"scanning indicators and triggered "
                f"{context.rule.rule_id} "
                f"({context.rule.name}). "
                f"The activity is consistent with "
                f"network service discovery. "
                f"The evidence establishes reconnaissance "
                f"activity, but does not establish that "
                f"the targeted system was compromised."
            )

        else:
            assessment = (
                f"The finding is associated with "
                f"{context.rule.rule_id} "
                f"({context.rule.name}), but Titan could "
                f"not independently confirm a recognized "
                f"reconnaissance indicator in the attached "
                f"Suricata evidence."
            )

        recommended_actions = [
            (
                "Validate whether the source IP belongs "
                "to an authorized scanner, administrator, "
                "or security-testing system."
            ),
            (
                "Review the Suricata signature and "
                "destination systems associated with the "
                "activity."
            ),
            (
                "Review additional traffic from the same "
                "source IP before and after the detection."
            ),
            (
                "Check endpoint telemetry on targeted "
                "systems for evidence of follow-on activity."
            ),
            (
                "Confirm whether the reconnaissance "
                "activity was expected or authorized."
            ),
            (
                "Escalate for investigation if the source "
                "is unknown or additional suspicious "
                "activity is observed."
            ),
        ]

    # ---------------------------------------------------------
    # AUTH-002
    # ---------------------------------------------------------

    elif rule_id == "AUTH-002":
        summary = (
            f"{analysis.failed_login_count} "
            f"failed login attempts were observed "
            f"from {context.subject}, targeting "
            f"{analysis.distinct_target_account_count} "
            f"distinct accounts over "
            f"{analysis.duration_seconds:.2f} seconds."
        )

        assessment = _build_auth_assessment(
            context,
            analysis,
        )

        recommended_actions = [
            (
                "Review the source IP address and "
                "determine whether it is expected."
            ),
            (
                "Verify whether the targeted email "
                "addresses correspond to real accounts."
            ),
            (
                "Review successful logins for the "
                "targeted accounts around the same time."
            ),
            (
                "Review additional authentication "
                "activity from the same source IP."
            ),
            (
                "Confirm whether the activity originated "
                "from testing, automation, or an approved "
                "security tool."
            ),
            (
                "Consider rate limiting or additional "
                "authentication protections if the "
                "activity continues."
            ),
        ]

    # ---------------------------------------------------------
    # AUTH-001 / AUTH-003
    # ---------------------------------------------------------

    elif rule_id in {
        "AUTH-001",
        "AUTH-003",
    }:
        summary = (
            f"{analysis.failed_login_count} "
            f"failed login attempts were observed "
            f"against {context.subject} over "
            f"{analysis.duration_seconds:.2f} seconds."
        )

        assessment = _build_auth_assessment(
            context,
            analysis,
        )

        recommended_actions = [
            (
                "Review the source IP address and "
                "determine whether it is expected."
            ),
            (
                "Review successful logins for the "
                "affected account around the same time."
            ),
            (
                "Confirm whether the account owner "
                "recognizes the authentication activity."
            ),
            (
                "Review additional authentication "
                "activity from the same source."
            ),
            (
                "Consider rate limiting or additional "
                "account protections if the activity "
                "continues."
            ),
        ]

    # ---------------------------------------------------------
    # Generic fallback
    # ---------------------------------------------------------

    else:
        summary = (
            f"Security finding {context.finding_type} "
            f"was observed for {context.subject} with "
            f"{context.evidence_count} attached "
            f"evidence event(s)."
        )

        assessment = (
            "Titan has preserved the finding and its "
            "evidence, but no rule-specific deterministic "
            "triage policy is currently available."
        )

        recommended_actions = [
            (
                "Review the evidence attached to the "
                "finding."
            ),
            (
                "Validate whether the activity is expected "
                "or authorized."
            ),
            (
                "Review related telemetry for additional "
                "suspicious activity."
            ),
        ]

    return TriageResult(
        summary=summary,
        risk_level=context.severity,
        assessment=assessment,
        recommended_actions=(
            recommended_actions
        ),
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


def _build_auth_assessment(
    context: TriageContext,
    analysis: TriageAnalysis,
) -> str:
    if (
        context.rule
        and analysis.threshold
        is not None
        and analysis.threshold_observed_value
        is not None
    ):
        if (
            analysis.threshold_metric
            == "failed_login_count"
        ):
            threshold_description = (
                f"{analysis.threshold_observed_value} "
                f"failed login attempts"
            )

        elif (
            analysis.threshold_metric
            == "distinct_target_account_count"
        ):
            threshold_description = (
                f"{analysis.threshold_observed_value} "
                f"distinct targeted accounts"
            )

        else:
            threshold_description = (
                f"an observed value of "
                f"{analysis.threshold_observed_value}"
            )

        window_description = (
            f" within "
            f"{context.rule.window_minutes} minutes"
            if context.rule.window_minutes
            is not None
            else ""
        )

        return (
            f"The activity triggered "
            f"{context.rule.rule_id} "
            f"({context.rule.name}) because "
            f"{threshold_description} met or exceeded "
            f"the configured threshold of "
            f"{analysis.threshold}"
            f"{window_description}."
        )

    return (
        "The finding contains suspicious "
        "authentication activity, but complete "
        "rule metadata is unavailable."
    )