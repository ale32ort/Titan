from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from app.db.base import Base


class AITriageRecord(Base):
    __tablename__ = "ai_triage_runs"
    __table_args__ = (
        Index(
            "uq_ai_triage_runs_one_running_per_finding",
            "finding_id",
            unique=True,
            postgresql_where=text(
                "status = 'running'"
            ),
            sqlite_where=text(
                "status = 'running'"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    finding_id: Mapped[str] = mapped_column(
        ForeignKey(
            "security_findings.id",
            ondelete="CASCADE",
        ),
        index=True,
        nullable=False,
    )

    requested_by_user_id: Mapped[
        str | None
    ] = mapped_column(
        String(36),
        nullable=True,
        index=True,
    )

    provider: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    model: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="running",
        index=True,
    )

    error_type: Mapped[
        str | None
    ] = mapped_column(
        String(100),
        nullable=True,
    )

    error_message: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    executive_summary: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    analyst_assessment: Mapped[
        str | None
    ] = mapped_column(
        Text,
        nullable=True,
    )

    confirmed_facts: Mapped[
        list | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    hypotheses: Mapped[
        list | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    missing_context: Mapped[
        list | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    recommended_actions: Mapped[
        list | None
    ] = mapped_column(
        JSON,
        nullable=True,
    )

    confidence: Mapped[
        str | None
    ] = mapped_column(
        String(20),
        nullable=True,
    )

    compromise_status: Mapped[
        str | None
    ] = mapped_column(
        String(30),
        nullable=True,
    )

    grounding_corrections: Mapped[
        list
    ] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(
            timezone.utc
        ),
        nullable=False,
    )

    completed_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )