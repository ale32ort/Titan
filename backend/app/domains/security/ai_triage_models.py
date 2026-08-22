from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AITriageRecord(Base):
    __tablename__ = "ai_triage_runs"

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

    requested_by_user_id: Mapped[str | None] = mapped_column(
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

    executive_summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    analyst_assessment: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    confirmed_facts: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    hypotheses: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    missing_context: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    recommended_actions: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
    )

    confidence: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    compromise_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    grounding_corrections: Mapped[list] = mapped_column(
        JSON,
        nullable=False,
        default=list,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )