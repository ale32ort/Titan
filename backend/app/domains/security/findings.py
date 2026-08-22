from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class SecurityFinding(Base):
    """A deduplicated security finding derived from one or more events."""

    __tablename__ = "security_findings"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid4()),
    )

    finding_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True,
    )

    subject: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="open",
        index=True,
    )

    trigger_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    rule_id: Mapped[str | None] = mapped_column(
    String(50),
    nullable=True,
    index=True,
    )
    
    assigned_to_user_id: Mapped[str | None] = mapped_column(
    String(36),
    nullable=True,
    index=True,
)


