from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.domains.identity.dependencies import (
    require_current_user,
)
from app.main import create_app

from conftest import (
    create_test_finding,
    create_test_user,
)


FINDINGS_URL = "/api/v1/security/findings"


def test_security_findings_returns_401_without_session(
    client: TestClient,
):
    response = client.get(
        FINDINGS_URL,
    )

    assert response.status_code == 401

    assert response.json() == {
        "detail": "Authentication required."
    }


def test_security_findings_returns_403_for_normal_user(
    db: Session,
):
    application = create_app()

    normal_user = create_test_user(
        db,
        email="normal-user@example.com",
        role="user",
    )

    def override_current_user():
        return normal_user

    from app.db.session import get_db

    def override_get_db():
        yield db

    application.dependency_overrides[
        get_db
    ] = override_get_db

    application.dependency_overrides[
        require_current_user
    ] = override_current_user

    with TestClient(application) as client:
        response = client.get(
            FINDINGS_URL,
        )

    application.dependency_overrides.clear()

    assert response.status_code == 403

    assert response.json() == {
        "detail": (
            "Security analyst access required."
        )
    }


def test_security_findings_returns_200_for_security_analyst(
    db: Session,
):
    application = create_app()

    analyst = create_test_user(
        db,
        email="analyst@example.com",
        role="security_analyst",
    )

    finding = create_test_finding(
        db,
    )

    def override_current_user():
        return analyst

    from app.db.session import get_db

    def override_get_db():
        yield db

    application.dependency_overrides[
        get_db
    ] = override_get_db

    application.dependency_overrides[
        require_current_user
    ] = override_current_user

    with TestClient(application) as client:
        response = client.get(
            FINDINGS_URL,
        )

    application.dependency_overrides.clear()

    assert response.status_code == 200

    body = response.json()

    assert len(body) == 1
    assert body[0]["id"] == finding.id
    assert body[0]["rule_id"] == "AUTH-001"
    assert (
        body[0]["finding_type"]
        == "AUTH_BRUTE_FORCE_SUSPECTED"
    )


def test_security_findings_returns_200_for_security_admin(
    db: Session,
):
    application = create_app()

    admin = create_test_user(
        db,
        email="security-admin@example.com",
        role="security_admin",
    )

    create_test_finding(
        db,
    )

    def override_current_user():
        return admin

    from app.db.session import get_db

    def override_get_db():
        yield db

    application.dependency_overrides[
        get_db
    ] = override_get_db

    application.dependency_overrides[
        require_current_user
    ] = override_current_user

    with TestClient(application) as client:
        response = client.get(
            FINDINGS_URL,
        )

    application.dependency_overrides.clear()

    assert response.status_code == 200