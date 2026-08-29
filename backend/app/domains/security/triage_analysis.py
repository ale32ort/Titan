from dataclasses import dataclass

from app.domains.security.detections.endpoint import (
    SUSPICIOUS_POWERSHELL_PATTERNS,
)
from app.domains.security.triage import TriageContext


RECON_KEYWORDS = (
    "recon",
    "reconnaissance",
    "scan",
    "scanner",
    "nmap",
    "port scan",
)


@dataclass(frozen=True)
class TriageAnalysis:
    # Authentication analysis
    failed_login_count: int
    successful_login_count: int
    success_after_failures: bool
    distinct_target_account_count: int
    unique_ip_count: int
    unique_user_agent_count: int

    # General timing / threshold analysis
    duration_seconds: float
    threshold: int | None
    threshold_metric: str | None
    threshold_observed_value: int | None
    threshold_exceeded_by: int | None

    # Network / Suricata analysis
    sensor_alert_count: int
    network_source_ip_count: int
    network_destination_ip_count: int
    network_destination_port_count: int
    network_protocol_count: int
    suricata_signature_count: int
    network_recon_evidence_present: bool

    # Endpoint / Sysmon analysis
    sysmon_process_create_count: int
    powershell_process_count: int
    suspicious_powershell_event_count: int
    endpoint_host_count: int
    suspicious_powershell_pattern_present: bool


def analyze_triage_context(
    context: TriageContext,
) -> TriageAnalysis:
    """
    Perform deterministic calculations over the evidence
    attached to a security finding.

    Titan performs these calculations before AI triage so the
    model receives evidence-backed facts rather than being asked
    to infer basic security invariants itself.
    """

    # ---------------------------------------------------------
    # Authentication evidence
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Network / Suricata evidence
    # ---------------------------------------------------------

    sensor_alert_events = [
        event
        for event in context.evidence
        if event.event_type
        == "SENSOR_SURICATA_ALERT"
    ]

    network_source_ips: set[str] = set()
    network_destination_ips: set[str] = set()
    network_destination_ports: set[str] = set()
    network_protocols: set[str] = set()
    suricata_signatures: set[str] = set()

    network_recon_evidence_present = False

    for event in sensor_alert_events:
        metadata = event.event_metadata or {}

        source_metadata = metadata.get(
            "source_metadata"
        )

        if not isinstance(
            source_metadata,
            dict,
        ):
            source_metadata = {}

        source_ip = (
            metadata.get("source_ip")
            or event.ip_address
        )

        destination_ip = metadata.get(
            "destination_ip"
        )

        destination_port = (
            source_metadata.get(
                "destination_port"
            )
            or source_metadata.get(
                "dest_port"
            )
        )

        protocol = (
            source_metadata.get(
                "protocol"
            )
            or source_metadata.get(
                "proto"
            )
        )

        signature = (
            source_metadata.get(
                "signature"
            )
            or metadata.get(
                "message"
            )
        )

        if source_ip:
            network_source_ips.add(
                str(source_ip)
            )

        if destination_ip:
            network_destination_ips.add(
                str(destination_ip)
            )

        if destination_port is not None:
            network_destination_ports.add(
                str(destination_port)
            )

        if protocol:
            network_protocols.add(
                str(protocol).upper()
            )

        if signature:
            signature_text = str(
                signature
            )

            suricata_signatures.add(
                signature_text
            )

            lowered_signature = (
                signature_text.lower()
            )

            if any(
                keyword in lowered_signature
                for keyword in RECON_KEYWORDS
            ):
                network_recon_evidence_present = (
                    True
                )

    # ---------------------------------------------------------
    # Endpoint / Sysmon evidence
    # ---------------------------------------------------------

    sysmon_process_events = [
        event
        for event in context.evidence
        if event.event_type
        == "SENSOR_SYSMON_PROCESS_CREATE"
    ]

    endpoint_hosts: set[str] = set()

    powershell_process_count = 0
    suspicious_powershell_event_count = 0

    for event in sysmon_process_events:
        metadata = event.event_metadata or {}

        source_metadata = metadata.get(
            "source_metadata"
        )

        if not isinstance(
            source_metadata,
            dict,
        ):
            source_metadata = {}

        host = (
            metadata.get("host")
            or context.subject
        )

        if host:
            endpoint_hosts.add(
                str(host)
            )

        image = str(
            source_metadata.get(
                "image"
            )
            or ""
        ).lower()

        command_line = str(
            source_metadata.get(
                "command_line"
            )
            or ""
        ).lower()

        is_powershell = (
            "powershell.exe" in image
            or "pwsh.exe" in image
        )

        if is_powershell:
            powershell_process_count += 1

            if any(
                pattern in command_line
                for pattern
                in SUSPICIOUS_POWERSHELL_PATTERNS
            ):
                suspicious_powershell_event_count += 1

    suspicious_powershell_pattern_present = (
        suspicious_powershell_event_count > 0
    )

    # ---------------------------------------------------------
    # Timing
    # ---------------------------------------------------------

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

    # ---------------------------------------------------------
    # Rule threshold interpretation
    # ---------------------------------------------------------

    threshold = (
        context.rule.threshold
        if context.rule
        else None
    )

    threshold_metric: str | None = None

    threshold_observed_value: (
        int | None
    ) = None

    if context.rule:
        if (
            context.rule.rule_id
            == "AUTH-001"
        ):
            threshold_metric = (
                "failed_login_count"
            )

            threshold_observed_value = (
                failed_login_count
            )

        elif (
            context.rule.rule_id
            == "AUTH-002"
        ):
            threshold_metric = (
                "distinct_target_account_count"
            )

            threshold_observed_value = len(
                targeted_accounts
            )

        elif (
            context.rule.rule_id
            == "AUTH-003"
        ):
            threshold_metric = (
                "failed_login_count"
            )

            threshold_observed_value = (
                failed_login_count
            )

    threshold_exceeded_by = (
        threshold_observed_value
        - threshold
        if (
            threshold is not None
            and threshold_observed_value
            is not None
        )
        else None
    )

    return TriageAnalysis(
        failed_login_count=(
            failed_login_count
        ),
        successful_login_count=(
            successful_login_count
        ),
        success_after_failures=(
            success_after_failures
        ),
        distinct_target_account_count=len(
            targeted_accounts
        ),
        unique_ip_count=len(
            unique_ips
        ),
        unique_user_agent_count=len(
            unique_user_agents
        ),
        duration_seconds=(
            duration_seconds
        ),
        threshold=threshold,
        threshold_metric=(
            threshold_metric
        ),
        threshold_observed_value=(
            threshold_observed_value
        ),
        threshold_exceeded_by=(
            threshold_exceeded_by
        ),
        sensor_alert_count=len(
            sensor_alert_events
        ),
        network_source_ip_count=len(
            network_source_ips
        ),
        network_destination_ip_count=len(
            network_destination_ips
        ),
        network_destination_port_count=len(
            network_destination_ports
        ),
        network_protocol_count=len(
            network_protocols
        ),
        suricata_signature_count=len(
            suricata_signatures
        ),
        network_recon_evidence_present=(
            network_recon_evidence_present
        ),
        sysmon_process_create_count=len(
            sysmon_process_events
        ),
        powershell_process_count=(
            powershell_process_count
        ),
        suspicious_powershell_event_count=(
            suspicious_powershell_event_count
        ),
        endpoint_host_count=len(
            endpoint_hosts
        ),
        suspicious_powershell_pattern_present=(
            suspicious_powershell_pattern_present
        ),
    )