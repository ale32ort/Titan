from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.domains.identity.sessions import (
    create_session,
    get_session_by_token,
    get_user_by_session_token,
    revoke_session,
)
from conftest import create_test_user


def test_create_session_returns_persisted_session_and_raw_token(
    db: Session,
):
    user = create_test_user(
        db,
        email="session-test@example.com",
        role="user",
    )

    session, raw_token = create_session(
        db,
        user.id,
    )

    assert session.id is not None
    assert session.user_id == user.id
    assert raw_token

    stored_session = get_session_by_token(
        db,
        raw_token,
    )

    assert stored_session is not None
    assert stored_session.id == session.id


def test_expired_session_is_rejected(
    db: Session,
):
    user = create_test_user(
        db,
        email="expired-session@example.com",
        role="user",
    )

    session, raw_token = create_session(
        db,
        user.id,
    )

    session.expires_at = (
        datetime.now(timezone.utc)
        - timedelta(minutes=1)
    )

    db.add(session)
    db.commit()

    stored_session = get_session_by_token(
        db,
        raw_token,
    )

    assert stored_session is None


def test_revoked_session_is_rejected(
    db: Session,
):
    user = create_test_user(
        db,
        email="revoked-session@example.com",
        role="user",
    )

    _, raw_token = create_session(
        db,
        user.id,
    )

    revoked = revoke_session(
        db,
        raw_token,
    )

    assert revoked is True

    stored_session = get_session_by_token(
        db,
        raw_token,
    )

    assert stored_session is None


def test_inactive_user_cannot_use_valid_session(
    db: Session,
):
    user = create_test_user(
        db,
        email="inactive-user@example.com",
        role="user",
    )

    _, raw_token = create_session(
        db,
        user.id,
    )

    user.is_active = False

    db.add(user)
    db.commit()

    authenticated_user = (
        get_user_by_session_token(
            db,
            raw_token,
        )
    )

    assert authenticated_user is None


def test_create_session_generates_unique_tokens(
    db: Session,
):
    user = create_test_user(
        db,
        email="unique-session@example.com",
        role="user",
    )

    _, first_token = create_session(
        db,
        user.id,
    )

    _, second_token = create_session(
        db,
        user.id,
    )

    assert first_token
    assert second_token
    assert first_token != second_token


def test_second_login_does_not_invalidate_first_session(
    db: Session,
):
    """
    Current Titan behavior allows multiple active
    sessions for the same user.

    This test documents that behavior explicitly.
    """

    user = create_test_user(
        db,
        email="multiple-session@example.com",
        role="user",
    )

    _, first_token = create_session(
        db,
        user.id,
    )

    _, second_token = create_session(
        db,
        user.id,
    )

    first_session = get_session_by_token(
        db,
        first_token,
    )

    second_session = get_session_by_token(
        db,
        second_token,
    )

    assert first_session is not None
    assert second_session is not None
    assert first_session.id != second_session.id