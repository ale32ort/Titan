from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.domains.security.evidence_service import get_finding_audit_events
from app.domains.security.rules import get_detection_rule
from app.db.session import get_db
from app.domains.identity.dependencies import (require_current_user, require_security_analyst)
from app.domains.identity.models import User
from app.domains.security.ai_triage_service import run_ai_triage
from app.domains.security.claude_client import ClaudeTriageClient
from app.domains.security.findings import SecurityFinding
from app.domains.security.schemas import (
    AITriageResponse,
    AITriageRunPublic,
    AuditEventEvidencePublic,
    DetectionRulePublic,
    SecurityFindingDetail,
    SecurityFindingPublic,
    SecurityFindingStatusUpdate,
    AnalystNoteCreate,
    AnalystNotePublic,
    CaseTimelineItem,
    SensorEventIngest,
SensorEventIngestResponse,
)
from app.domains.security.service import record_audit_event
from app.domains.security.ai_triage_record_service import (
    get_ai_triage_records_for_finding,
)
from app.domains.security.ai_triage_record_service import (
    get_ai_triage_record,
    get_ai_triage_records_for_finding,
)
from app.domains.security.analyst_note_service import (
    create_analyst_note,
    get_analyst_notes_for_finding,
)

from app.domains.security.timeline import (
    build_case_timeline,
)
from app.domains.identity.csrf import require_csrf_token
from app.domains.security.ingestion_auth import (
    require_sensor_api_key,
)

from app.domains.security.ingestion_service import (
    ingest_sensor_event,
)

router = APIRouter(
    prefix="/security",
    tags=["security"],
)

@router.post(
    "/ingest/events",
    response_model=SensorEventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
def ingest_security_event(
    payload: SensorEventIngest,
    sensor_authenticated: None = Depends(
        require_sensor_api_key
    ),
    db: Session = Depends(get_db),
) -> SensorEventIngestResponse:
    """
    Accept normalized telemetry from an
    authenticated Titan sensor.
    """

    event = ingest_sensor_event(
        db,
        payload=payload,
    )

    return SensorEventIngestResponse(
        event_id=event.id,
        source=payload.source,
        event_type=event.event_type,
        status="accepted",
        created_at=event.created_at,
    )


@router.get(
    "/findings",
    response_model=list[SecurityFindingPublic],
)
def list_security_findings(
    current_user: User = Depends(require_security_analyst),
    db: Session = Depends(get_db),
) -> list[SecurityFindingPublic]:
    """Return security findings ordered by most recently observed."""

    findings = db.scalars(
        select(SecurityFinding)
        .order_by(SecurityFinding.last_seen.desc())
    ).all()

    return [
        SecurityFindingPublic.model_validate(finding)
        for finding in findings
    ]


@router.get(
    "/findings/{finding_id}",
    response_model=SecurityFindingDetail,
)
def get_security_finding(
    finding_id: str,
    current_user: User = Depends(require_security_analyst),
    db: Session = Depends(get_db),
) -> SecurityFindingDetail:
    """Return a security finding and its supporting evidence."""

    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    audit_events = get_finding_audit_events(
        db,
        finding_id=finding.id,
    )

    rule = (
        get_detection_rule(finding.rule_id)
        if finding.rule_id
        else None
    )

    return SecurityFindingDetail(
        id=finding.id,
        finding_type=finding.finding_type,
        subject=finding.subject,
        severity=finding.severity,
        status=finding.status,
        assigned_to_user_id=finding.assigned_to_user_id,
        trigger_count=finding.trigger_count,
        rule_id=finding.rule_id,
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
         rule=(
            DetectionRulePublic(
                rule_id=rule.rule_id,
                name=rule.name,
                description=rule.description,
                severity=rule.severity,
                threshold=rule.threshold,
                window_minutes=rule.window_minutes,
                mitre_tactic=rule.mitre_tactic,
                mitre_technique_id=rule.mitre_technique_id,
                mitre_technique_name=rule.mitre_technique_name,
            )
            if rule
            else None
         ),
         evidence_count=len(audit_events),
        evidence=[
            AuditEventEvidencePublic.model_validate(event)
            for event in audit_events
        ],
    )


@router.patch(
    "/findings/{finding_id}/status",
    response_model=SecurityFindingPublic,
)
def update_security_finding_status(
    finding_id: str,
    payload: SecurityFindingStatusUpdate,
    request: Request,
    csrf_valid: None = Depends(require_csrf_token),
    current_user: User = Depends(require_security_analyst),
    db: Session = Depends(get_db),
) -> SecurityFindingPublic:
    """Update the analyst status of a security finding."""

    allowed_statuses = {
        "open",
        "investigating",
        "resolved",
    }

    if payload.status not in allowed_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Invalid status. "
                "Allowed values: open, investigating, resolved."
            ),
        )

    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    previous_status = finding.status
    finding.status = payload.status

    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        event_type="SECURITY_FINDING_STATUS_CHANGED",
        result="success",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        event_metadata={
            "finding_id": finding.id,
            "finding_type": finding.finding_type,
            "previous_status": previous_status,
            "new_status": finding.status,
        },
    )

    return SecurityFindingPublic.model_validate(finding)

@router.post(
    "/findings/{finding_id}/triage",
    response_model=AITriageResponse,
)
def triage_security_finding(
    finding_id: str,
    csrf_valid: None = Depends(require_csrf_token),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> AITriageResponse:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    try:
        ai_client = ClaudeTriageClient()

        triage_run = run_ai_triage(
            db,
            finding=finding,
            ai_client=ai_client,
            requested_by_user_id=current_user.id,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="AI triage provider failed.",
        ) from exc

    return AITriageResponse(
        triage_run_id=triage_run.record.id,
        finding_id=finding.id,
        deterministic_summary=triage_run.deterministic_result.summary,
        ai_result=triage_run.grounding.output.model_dump(),
        grounding_corrections=triage_run.grounding.corrections,
    )

@router.get(
    "/findings/{finding_id}/triage-runs",
    response_model=list[AITriageRunPublic],
)
def list_triage_runs_for_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> list[AITriageRunPublic]:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    records = get_ai_triage_records_for_finding(
        db,
        finding_id=finding.id,
    )

    return [
        AITriageRunPublic.model_validate(record)
        for record in records
    ]

@router.get(
    "/triage-runs/{triage_run_id}",
    response_model=AITriageRunPublic,
)
def get_triage_run(
    triage_run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> AITriageRunPublic:
    record = get_ai_triage_record(
        db,
        triage_run_id=triage_run_id,
    )

    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AI triage run not found.",
        )

    return AITriageRunPublic.model_validate(record)

@router.post(
    "/findings/{finding_id}/notes",
    response_model=AnalystNotePublic,
    status_code=status.HTTP_201_CREATED,
)
def add_analyst_note(
    finding_id: str,
    payload: AnalystNoteCreate,
    csrf_valid: None = Depends(require_csrf_token),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> AnalystNotePublic:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    content = payload.content.strip()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Analyst note cannot be empty.",
        )

    note = create_analyst_note(
        db,
        finding_id=finding.id,
        author_user_id=current_user.id,
        content=content,
    )

    return AnalystNotePublic.model_validate(
        note
    )

@router.get(
    "/findings/{finding_id}/notes",
    response_model=list[AnalystNotePublic],
)
def list_analyst_notes(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> list[AnalystNotePublic]:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    notes = get_analyst_notes_for_finding(
        db,
        finding_id=finding.id,
    )

    return [
        AnalystNotePublic.model_validate(note)
        for note in notes
    ]

@router.post(
    "/findings/{finding_id}/assign-to-me",
    response_model=SecurityFindingPublic,
)
def assign_finding_to_me(
    finding_id: str,
    csrf_valid: None = Depends(require_csrf_token),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> SecurityFindingPublic:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    previous_assigned_to_user_id = (
        finding.assigned_to_user_id
    )

    finding.assigned_to_user_id = current_user.id

    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        event_type="SECURITY_FINDING_ASSIGNED",
        result="success",
        user_id=current_user.id,
        email=current_user.email,
        event_metadata={
            "finding_id": finding.id,
            "previous_assigned_to_user_id": (
                previous_assigned_to_user_id
            ),
            "assigned_to_user_id": current_user.id,
        },
    )

    return SecurityFindingPublic.model_validate(
        finding
    )


@router.post(
    "/findings/{finding_id}/unassign",
    response_model=SecurityFindingPublic,
)
def unassign_finding(
    finding_id: str,
    csrf_valid: None = Depends(require_csrf_token),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_security_analyst),
) -> SecurityFindingPublic:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    previous_assigned_to_user_id = (
        finding.assigned_to_user_id
    )

    finding.assigned_to_user_id = None

    db.add(finding)
    db.commit()
    db.refresh(finding)

    record_audit_event(
        db,
        event_type="SECURITY_FINDING_UNASSIGNED",
        result="success",
        user_id=current_user.id,
        email=current_user.email,
        event_metadata={
            "finding_id": finding.id,
            "previous_assigned_to_user_id": (
                previous_assigned_to_user_id
            ),
            "assigned_to_user_id": None,
        },
    )

    return SecurityFindingPublic.model_validate(
        finding
    )

@router.get(
    "/findings/{finding_id}/timeline",
    response_model=list[CaseTimelineItem],
)
def get_case_timeline(
    finding_id: str,
    current_user: User = Depends(
        require_security_analyst
    ),
    db: Session = Depends(get_db),
) -> list[CaseTimelineItem]:
    finding = db.get(
        SecurityFinding,
        finding_id,
    )

    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Security finding not found.",
        )

    timeline = build_case_timeline(
        db,
        finding=finding,
    )

    return [
        CaseTimelineItem.model_validate(
            item
        )
        for item in timeline
    ]