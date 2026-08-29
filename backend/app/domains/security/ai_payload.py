from dataclasses import asdict, dataclass
from typing import Any

from app.domains.security.triage import (
    TriageContext,
    TriageEvidence,
)
from app.domains.security.triage_analysis import (
    TriageAnalysis,
)
from app.domains.security.triage_result import (
    TriageResult,
)


@dataclass(frozen=True)
class AIInputPayload:
    finding_id: str
    finding_type: str
    subject: str
    severity: str
    status: str

    rule: dict[str, Any] | None

    analysis: dict[str, Any]

    deterministic_result: dict[str, Any]

    evidence: list[dict[str, Any]]


def build_ai_input_payload(
    context: TriageContext,
    analysis: TriageAnalysis,
    result: TriageResult,
) -> AIInputPayload:
    rule_payload = (
        asdict(context.rule)
        if context.rule
        else None
    )

    evidence_payload = [
        _build_evidence_payload(event)
        for event in context.evidence
    ]

    return AIInputPayload(
        finding_id=context.finding_id,
        finding_type=context.finding_type,
        subject=context.subject,
        severity=context.severity,
        status=context.status,
        rule=rule_payload,
        analysis=asdict(analysis),
        deterministic_result=asdict(result),
        evidence=evidence_payload,
    )


def _build_evidence_payload(
    event: TriageEvidence,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "email": event.email,
        "ip_address": event.ip_address,
        "result": event.result,
        "created_at": (
            event.created_at.isoformat()
        ),
    }

    if (
        event.event_type
        == "SENSOR_SURICATA_ALERT"
    ):
        payload["sensor"] = (
            _build_suricata_metadata(
                event.event_metadata
            )
        )

    elif (
        event.event_type
        == "SENSOR_SYSMON_PROCESS_CREATE"
    ):
        payload["sensor"] = (
            _build_sysmon_metadata(
                event.event_metadata
            )
        )

    return payload


def _build_suricata_metadata(
    event_metadata: dict[str, Any]
    | None,
) -> dict[str, Any]:
    metadata = event_metadata or {}

    source_metadata = metadata.get(
        "source_metadata"
    )

    if not isinstance(
        source_metadata,
        dict,
    ):
        source_metadata = {}

    return {
        "source": metadata.get(
            "source"
        ),
        "sensor_event_type": metadata.get(
            "sensor_event_type"
        ),
        "host": metadata.get(
            "host"
        ),
        "source_ip": metadata.get(
            "source_ip"
        ),
        "destination_ip": metadata.get(
            "destination_ip"
        ),
        "severity": metadata.get(
            "severity"
        ),
        "message": metadata.get(
            "message"
        ),
        "observed_at": metadata.get(
            "observed_at"
        ),
        "signature": source_metadata.get(
            "signature"
        ),
        "signature_id": source_metadata.get(
            "signature_id"
        ),
        "category": source_metadata.get(
            "category"
        ),
        "action": source_metadata.get(
            "action"
        ),
        "protocol": (
            source_metadata.get(
                "protocol"
            )
            or source_metadata.get(
                "proto"
            )
        ),
        "source_port": source_metadata.get(
            "source_port"
        ),
        "destination_port": (
            source_metadata.get(
                "destination_port"
            )
            or source_metadata.get(
                "dest_port"
            )
        ),
        "flow_id": source_metadata.get(
            "flow_id"
        ),
    }

def _build_sysmon_metadata(
    event_metadata: dict[str, Any]
    | None,
) -> dict[str, Any]:
    """
    Build the restricted subset of Sysmon evidence
    that Titan permits into the AI triage payload.

    Arbitrary event metadata is intentionally not
    forwarded to the AI provider.
    """

    metadata = event_metadata or {}

    source_metadata = metadata.get(
        "source_metadata"
    )

    if not isinstance(
        source_metadata,
        dict,
    ):
        source_metadata = {}

    return {
        "source": metadata.get(
            "source"
        ),
        "sensor_event_type": metadata.get(
            "sensor_event_type"
        ),
        "host": metadata.get(
            "host"
        ),
        "severity": metadata.get(
            "severity"
        ),
        "message": metadata.get(
            "message"
        ),
        "observed_at": metadata.get(
            "observed_at"
        ),
        "image": source_metadata.get(
            "image"
        ),
        "command_line": source_metadata.get(
            "command_line"
        ),
        "parent_image": source_metadata.get(
            "parent_image"
        ),
        "parent_command_line": (
            source_metadata.get(
                "parent_command_line"
            )
        ),
        "user": source_metadata.get(
            "user"
        ),
        "user_domain": source_metadata.get(
            "user_domain"
        ),
        "process_id": source_metadata.get(
            "process_id"
        ),
        "process_guid": source_metadata.get(
            "process_guid"
        ),
        "parent_process_id": (
            source_metadata.get(
                "parent_process_id"
            )
        ),
        "parent_process_guid": (
            source_metadata.get(
                "parent_process_guid"
            )
        ),
        "record_id": source_metadata.get(
            "record_id"
        ),
        "elastic_document_id": (
            source_metadata.get(
                "elastic_document_id"
            )
        ),
    }