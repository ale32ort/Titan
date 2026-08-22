from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.domains.identity.models import User
from app.domains.identity.sessions import get_user_by_session_token


def require_current_user(
    titan_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> User:
    """Require and return the currently authenticated user."""

    if titan_session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    user = get_user_by_session_token(
        db,
        titan_session,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session.",
        )

    return user

def require_security_analyst(
    current_user: User = Depends(require_current_user),
) -> User:
    """
    Require the authenticated user to have SOC access.

    security_analyst:
        Can access and investigate security findings.

    security_admin:
        Inherits analyst access and will later receive
        additional security-administration permissions.
    """

    allowed_roles = {
        "security_analyst",
        "security_admin",
    }

    if current_user.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Security analyst access required.",
        )

    return current_user