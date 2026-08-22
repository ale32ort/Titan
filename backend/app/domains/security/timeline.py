from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.security.ai_triage_models import AITriageRecord
from app.domains.security.analyst_notes import AnalystNote
from app.domains.security.findings import SecurityFinding
from app.domains.security.models import AuditEvent


def build_case_timeline(
    db: Session,
    *,
    finding: SecurityFinding,
) -> list[dict[str, Any]]:
    """
    Build a normalized chronological activity timeline for one security finding.

    The timeline does not become a new source of truth.
    It reads existing persisted records and presents them in one format.
    """

    timeline: list[dict[str, Any]] = []

    # ---------------------------------------------------------
    # 1. Finding creation
    # ---------------------------------------------------------

    timeline.append(
        {
            "event_type": "FINDING_CREATED",
            "title": "Security finding created",
            "description": (
                f"{finding.finding_type} was opened for "
                f"{finding.subject}."
            ),
            "actor_user_id": None,
            "created_at": finding.first_seen,
            "metadata": {
                "finding_id": finding.id,
                "severity": finding.severity,
                "rule_id": finding.rule_id,
            },
        }
    )

    # ---------------------------------------------------------
    # 2. Security audit events associated with this finding
    # ---------------------------------------------------------

    audit_statement = (
        select(AuditEvent)
        .where(
            AuditEvent.event_metadata.is_not(None),
            AuditEvent.event_metadata["finding_id"].as_string()
            == finding.id,
        )
        .order_by(AuditEvent.created_at.asc())
    )

    audit_events = list(
        db.scalars(audit_statement).all()
    )

    for event in audit_events:
        metadata = event.event_metadata or {}

        title = event.event_type.replace(
            "_",
            " ",
        ).title()

        description = _audit_description(
            event.event_type,
            metadata,
        )

        timeline.append(
            {
                "event_type": event.event_type,
                "title": title,
                "description": description,
                "actor_user_id": event.user_id,
                "created_at": event.created_at,
                "metadata": metadata,
            }
        )

    # ---------------------------------------------------------
    # 3. Analyst notes
    # ---------------------------------------------------------

    notes_statement = (
        select(AnalystNote)
        .where(
            AnalystNote.finding_id
            == finding.id
        )
        .order_by(
            AnalystNote.created_at.asc()
        )
    )

    notes = list(
        db.scalars(notes_statement).all()
    )

    for note in notes:
        timeline.append(
            {
                "event_type": "ANALYST_NOTE_ADDED",
                "title": "Analyst note added",
                "description": note.content,
                "actor_user_id": note.author_user_id,
                "created_at": note.created_at,
                "metadata": {
                    "note_id": note.id,
                },
            }
        )

    # ---------------------------------------------------------
    # 4. AI triage runs
    # ---------------------------------------------------------

    triage_statement = (
        select(AITriageRecord)
        .where(
            AITriageRecord.finding_id
            == finding.id
        )
        .order_by(
            AITriageRecord.created_at.asc()
        )
    )

    triage_runs = list(
        db.scalars(triage_statement).all()
    )

    for run in triage_runs:
        timeline.append(
            {
                "event_type": "AI_TRIAGE_COMPLETED",
                "title": "AI triage completed",
                "description": (
                    f"{run.model} completed triage with "
                    f"{run.confidence} confidence. "
                    f"Compromise status: "
                    f"{run.compromise_status}."
                ),
                "actor_user_id": (
                    run.requested_by_user_id
                ),
                "created_at": run.created_at,
                "metadata": {
                    "triage_run_id": run.id,
                    "provider": run.provider,
                    "model": run.model,
                    "confidence": run.confidence,
                    "compromise_status": (
                        run.compromise_status
                    ),
                    "grounding_corrections": (
                        run.grounding_corrections
                    ),
                },
            }
        )

    # ---------------------------------------------------------
    # 5. Put everything in chronological order
    # ---------------------------------------------------------

    timeline.sort(
        key=lambda item: item["created_at"]
    )

    return timeline


def _audit_description(
    event_type: str,
    metadata: dict,
) -> str:
    """Convert known audit events into readable case activity."""

    if event_type == "SECURITY_FINDING_STATUS_CHANGED":
        previous_status = metadata.get(
            "previous_status",
            "unknown",
        )

        new_status = metadata.get(
            "new_status",
            "unknown",
        )

        return (
            f"Finding status changed from "
            f"{previous_status} to {new_status}."
        )

    if event_type == "SECURITY_FINDING_ASSIGNED":
        assigned_to = metadata.get(
            "assigned_to_user_id"
        )

        return (
            f"Finding assigned to analyst "
            f"{assigned_to}."
        )

    if event_type == "SECURITY_FINDING_UNASSIGNED":
        previous_assignee = metadata.get(
            "previous_assigned_to_user_id"
        )

        if previous_assignee:
            return (
                f"Finding unassigned from analyst "
                f"{previous_assignee}."
            )

        return "Finding was unassigned."

    return event_type.replace(
        "_",
        " ",
    ).capitalize()