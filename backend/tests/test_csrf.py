from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app.core.config import settings
from app.domains.identity.csrf import (
    create_csrf_token,
    require_csrf_token,
    validate_csrf_token,
)


def test_csrf_token_validates_for_same_session():
    session_token = "test-session-token-alpha"

    csrf_token = create_csrf_token(
        session_token
    )

    assert validate_csrf_token(
        session_token=session_token,
        csrf_token=csrf_token,
    ) is True


def test_csrf_token_rejected_for_different_session():
    session_a = "test-session-token-alpha"
    session_b = "test-session-token-bravo"

    csrf_token = create_csrf_token(
        session_a
    )

    assert validate_csrf_token(
        session_token=session_b,
        csrf_token=csrf_token,
    ) is False


def test_csrf_token_rejected_when_modified():
    session_token = "test-session-token-alpha"

    csrf_token = create_csrf_token(
        session_token
    )

    tampered_token = (
        csrf_token[:-1]
        + (
            "0"
            if csrf_token[-1] != "0"
            else "1"
        )
    )

    assert validate_csrf_token(
        session_token=session_token,
        csrf_token=tampered_token,
    ) is False


def create_csrf_test_app() -> FastAPI:
    app = FastAPI()

    @app.post("/protected")
    def protected(
        csrf_valid: None = Depends(
            require_csrf_token
        ),
    ):
        return {
            "status": "allowed"
        }

    return app


def test_csrf_protected_route_rejects_missing_token():
    app = create_csrf_test_app()

    with TestClient(app) as client:
        response = client.post(
            "/protected"
        )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "CSRF validation failed."
    }


def test_csrf_protected_route_accepts_valid_token():
    app = create_csrf_test_app()

    session_token = "csrf-api-session"

    csrf_token = create_csrf_token(
        session_token
    )

    with TestClient(app) as client:
        response = client.post(
            "/protected",
            cookies={
                settings.SESSION_COOKIE_NAME:
                    session_token,
                settings.CSRF_COOKIE_NAME:
                    csrf_token,
            },
            headers={
                settings.CSRF_HEADER_NAME:
                    csrf_token,
            },
        )

    assert response.status_code == 200

    assert response.json() == {
        "status": "allowed"
    }


def test_csrf_protected_route_rejects_wrong_header():
    app = create_csrf_test_app()

    session_token = "csrf-api-session"

    csrf_token = create_csrf_token(
        session_token
    )

    with TestClient(app) as client:
        response = client.post(
            "/protected",
            cookies={
                settings.SESSION_COOKIE_NAME:
                    session_token,
                settings.CSRF_COOKIE_NAME:
                    csrf_token,
            },
            headers={
                settings.CSRF_HEADER_NAME:
                    "tampered-token",
            },
        )

    assert response.status_code == 403

    assert response.json() == {
        "detail": "CSRF validation failed."
    }