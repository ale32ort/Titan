from sqlalchemy.orm import Session

from app.core.config import settings
from app.domains.identity.csrf import (
    create_csrf_token,
)
from app.domains.identity.sessions import (
    create_session,
    get_session_by_token,
)
from conftest import create_test_user


def _set_session_cookies(
    client,
    *,
    session_token: str,
    csrf_token: str,
) -> None:
    client.cookies.set(
        settings.SESSION_COOKIE_NAME,
        session_token,
        domain="testserver.local",
        path="/",
    )

    client.cookies.set(
        settings.CSRF_COOKIE_NAME,
        csrf_token,
        domain="testserver.local",
        path="/",
    )


def test_logout_rejects_missing_csrf(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        email="logout-missing-csrf@example.com",
    )

    _, session_token = create_session(
        db,
        user.id,
    )

    csrf_token = create_csrf_token(
        session_token
    )

    _set_session_cookies(
        client,
        session_token=session_token,
        csrf_token=csrf_token,
    )

    response = client.post(
        "/api/v1/auth/logout"
    )

    assert response.status_code == 403

    # Failed CSRF validation must not revoke
    # the authenticated session.
    assert (
        get_session_by_token(
            db,
            session_token,
        )
        is not None
    )


def test_logout_rejects_invalid_csrf(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        email="logout-invalid-csrf@example.com",
    )

    _, session_token = create_session(
        db,
        user.id,
    )

    csrf_token = create_csrf_token(
        session_token
    )

    _set_session_cookies(
        client,
        session_token=session_token,
        csrf_token=csrf_token,
    )

    response = client.post(
        "/api/v1/auth/logout",
        headers={
            settings.CSRF_HEADER_NAME:
                "invalid-csrf-token",
        },
    )

    assert response.status_code == 403

    assert (
        get_session_by_token(
            db,
            session_token,
        )
        is not None
    )


def test_logout_with_valid_csrf_revokes_session(
    client,
    db: Session,
):
    user = create_test_user(
        db,
        email="logout-success@example.com",
    )

    _, session_token = create_session(
        db,
        user.id,
    )

    csrf_token = create_csrf_token(
        session_token
    )

    _set_session_cookies(
        client,
        session_token=session_token,
        csrf_token=csrf_token,
    )

    response = client.post(
        "/api/v1/auth/logout",
        headers={
            settings.CSRF_HEADER_NAME:
                csrf_token,
        },
    )

    assert response.status_code == 204

    # The server-side session must be revoked.
    assert (
        get_session_by_token(
            db,
            session_token,
        )
        is None
    )

    # TestClient should process the Set-Cookie
    # deletions returned by the logout endpoint.
    assert (
        settings.SESSION_COOKIE_NAME
        not in client.cookies
    )

    assert (
        settings.CSRF_COOKIE_NAME
        not in client.cookies
    )