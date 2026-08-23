from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base

# Import models so SQLAlchemy knows about every table
# used by these tests before Base.metadata.create_all().
from app.domains.security.evidence import FindingEvidence  # noqa: F401
from app.domains.security.findings import SecurityFinding  # noqa: F401
from app.domains.security.models import AuditEvent


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    """
    Give each test an isolated in-memory SQLite database.

    Nothing written here can touch Titan's normal PostgreSQL
    development database.
    """

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={
            "check_same_thread": False,
        },
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_sqlite_foreign_keys(
        dbapi_connection,
        connection_record,
    ):
        del connection_record

        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)

    TestingSessionLocal = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )

    session = TestingSessionLocal()

    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def create_audit_event(
    db: Session,
    *,
    event_type: str,
    email: str | None = None,
    ip_address: str | None = None,
    result: str,
    created_at: datetime | None = None,
) -> AuditEvent:
    """
    Test helper for inserting security telemetry.
    """

    audit_event = AuditEvent(
        event_type=event_type,
        email=email,
        result=result,
        ip_address=ip_address,
        user_agent="pytest-agent",
        created_at=created_at or datetime.now(timezone.utc),
        event_metadata={
            "source": "pytest",
        },
    )

    db.add(audit_event)
    db.commit()
    db.refresh(audit_event)

    return audit_event