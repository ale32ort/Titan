from datetime import datetime, timezone
from app.domains.security.detections.network import (
    detect_network_reconnaissance,
)
from sqlalchemy.orm import Session
from app.domains.security.detections.endpoint import (
    detect_suspicious_powershell,
)
from app.domains.security.models import AuditEvent
from app.domains.security.schemas import (
    SensorEventIngest,
)


def ingest_sensor_event(
    db: Session,
    *,
    payload: SensorEventIngest,
) -> AuditEvent:
    """
    Normalize an external sensor event into Titan's
    canonical security-event store.
    """

    observed_at = (
        payload.observed_at
        or datetime.now(timezone.utc)
    )

    normalized_event_type = (
        f"SENSOR_{payload.source.upper()}_"
        f"{payload.event_type.upper()}"
    )

    normalized_event_type = (
        normalized_event_type
        .replace(" ", "_")
        .replace("-", "_")
    )

    event_metadata = {
        "sensor_source": payload.source,
        "sensor_event_type": payload.event_type,
        "host": payload.host,
        "source_ip": payload.source_ip,
        "destination_ip": (
            payload.destination_ip
        ),
        "severity": payload.severity,
        "message": payload.message,
        "observed_at": (
            observed_at.isoformat()
        ),
        "source_metadata": payload.metadata,
    }

    event = AuditEvent(
        event_type=normalized_event_type,
        result="observed",
        ip_address=payload.source_ip,
        event_metadata=event_metadata,
        created_at=observed_at,
    )

    db.add(event)
    db.commit()
    db.refresh(event)

    detect_network_reconnaissance(
    db,
    event_id=event.id,
)

    detect_suspicious_powershell(
    db,
    event_id=event.id,
)

    return event