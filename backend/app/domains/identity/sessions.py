import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.domains.identity.models import User


from app.domains.identity.session_models import UserSession


SESSION_TTL_HOURS = 12


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user_id: str,
) -> tuple[UserSession, str]:
    """Create a new server-managed session."""

    raw_token = secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    session = UserSession(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=datetime.now(timezone.utc)
        + timedelta(hours=SESSION_TTL_HOURS),
    )

    db.add(session)
    db.commit()
    db.refresh(session)

    return session, raw_token


def get_session_by_token(
    db: Session,
    raw_token: str,
) -> UserSession | None:
    """Resolve a raw session token to an active session."""

    token_hash = _hash_token(raw_token)

    session = db.scalar(
        select(UserSession).where(
            UserSession.token_hash == token_hash
        )
    )

    if session is None:
        return None

    if session.revoked_at is not None:
        return None

    if session.expires_at <= datetime.now(timezone.utc):
        return None

    return session

def get_user_by_session_token(
    db: Session,
    raw_token: str,
) -> User | None:
    """Return the authenticated user for an active session token."""

    session = get_session_by_token(
        db,
        raw_token,
    )

    if session is None:
        return None

    user = db.scalar(
        select(User).where(
            User.id == session.user_id
        )
    )

    if user is None:
        return None

    if not user.is_active:
        return None

    return user

def revoke_session(
    db: Session,
    raw_token: str,
) -> bool:
    """Revoke an active session token."""

    session = get_session_by_token(
        db,
        raw_token,
    )

    if session is None:
        return False

    session.revoked_at = datetime.now(timezone.utc)

    db.add(session)
    db.commit()

    return True