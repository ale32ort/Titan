import os

# ---------------------------------------------------------
# Test-only configuration
#
# These values must be established before Titan modules are
# imported so pytest never loads real development secrets
# from backend/.env.
# ---------------------------------------------------------

os.environ["ENVIRONMENT"] = "test"
os.environ["DEBUG"] = "False"

os.environ["SECRET_KEY"] = (
    "pytest-secret-key-not-for-production"
)

os.environ["SENSOR_INGEST_API_KEY"] = (
    "pytest-sensor-key"
)

os.environ["DATABASE_URL"] = (
    "sqlite+pysqlite:///:memory:"
)

os.environ["ANTHROPIC_API_KEY"] = ""
os.environ["ANTHROPIC_MODEL"] = (
    "claude-sonnet-5"
)
from collections.abc import Generator
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_db
from app.main import create_app

# Explicit model imports ensure SQLAlchemy knows the
# tables needed by the tests before create_all().
from app.domains.identity.models import User
from app.domains.identity.session_models import UserSession  # noqa: F401
from app.domains.security.evidence import FindingEvidence  # noqa: F401
from app.domains.security.findings import SecurityFinding
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


@pytest.fixture()
def client(
    db: Session,
) -> Generator[TestClient, None, None]:
    """
    Create Titan's real FastAPI application while replacing
    only its database dependency with the isolated test DB.
    """

    application = create_app()

    def override_get_db():
        yield db

    application.dependency_overrides[
        get_db
    ] = override_get_db

    with TestClient(application) as test_client:
        yield test_client

    application.dependency_overrides.clear()


def create_test_user(
    db: Session,
    *,
    email: str,
    role: str = "user",
) -> User:
    """
    Create an authenticated-user object for RBAC/API tests.

    Password verification is not part of these authorization
    tests, so the password hash is a harmless placeholder.
    """

    user = User(
        email=email,
        first_name="Titan",
        last_name="Tester",
        password_hash="test-only-hash",
        is_active=True,
        is_verified=True,
        role=role,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user


def create_test_finding(
    db: Session,
) -> SecurityFinding:
    """
    Create one finding so authorized analysts receive
    a meaningful successful API response.
    """

    finding = SecurityFinding(
        finding_type="AUTH_BRUTE_FORCE_SUSPECTED",
        subject="rbac-target@example.com",
        severity="high",
        status="open",
        trigger_count=1,
        rule_id="AUTH-001",
    )

    db.add(finding)
    db.commit()
    db.refresh(finding)

    return finding


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
        created_at=(
            created_at
            or datetime.now(timezone.utc)
        ),
        event_metadata={
            "source": "pytest",
        },
    )

    db.add(audit_event)
    db.commit()
    db.refresh(audit_event)

    return audit_event