from sqlalchemy.orm import Session

from app.domains.identity.sessions import (
    create_session,
    get_session_by_token,
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