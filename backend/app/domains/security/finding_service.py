from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.security.findings import SecurityFinding


def upsert_security_finding(
    db: Session,
    *,
    finding_type: str,
    subject: str,
    severity: str,
    rule_id: str | None = None,
) -> SecurityFinding:
    finding = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.finding_type == finding_type,
            SecurityFinding.subject == subject,
            SecurityFinding.status == "open",
        )
    )

    if finding:
        finding.trigger_count += 1
        finding.last_seen = datetime.now(timezone.utc)

        if rule_id and not finding.rule_id:
            finding.rule_id = rule_id

        db.commit()
        db.refresh(finding)
        return finding

    finding = SecurityFinding(
        finding_type=finding_type,
        subject=subject,
        severity=severity,
        rule_id=rule_id,
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding