from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.identity.models import User
from app.domains.identity.passwords import hash_password
from app.domains.identity.schemas import UserRegistrationRequest


def register_user(
    db: Session,
    payload: UserRegistrationRequest,
) -> User:
    """Create and persist a new user account."""

    existing_user = db.scalar(
        select(User).where(User.email == payload.email)
    )

    if existing_user is not None:
        raise ValueError("A user with that email already exists.")

    user = User(
        email=payload.email,
        first_name=payload.first_name,
        last_name=payload.last_name,
        password_hash=hash_password(payload.password),
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    return user

from app.domains.identity.passwords import (
    hash_password,
    verify_password,
)
from app.domains.identity.schemas import (
    UserLoginRequest,
    UserRegistrationRequest,
)


def authenticate_user(
    db: Session,
    payload: UserLoginRequest,
) -> User | None:
    """Authenticate a user by email and password."""

    user = db.scalar(
        select(User).where(User.email == payload.email)
    )

    if user is None:
        return None

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        return None

    if not user.is_active:
        return None

    return user