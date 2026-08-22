from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    __table_args__ = (
        UniqueConstraint(
            "finding_id",
            "audit_event_id",
            name="uq_finding_evidence_finding_audit_event",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    finding_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("security_findings.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    audit_event_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("audit_events.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )