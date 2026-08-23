from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from app.core.config import settings
from sqlalchemy.orm import Session
from app.domains.security.detections.authentication import (
    detect_repeated_login_failures, detect_password_spray, detect_success_after_failures
)
from app.db.session import get_db
from app.domains.identity.dependencies import require_current_user
from app.domains.identity.models import User
from app.domains.identity.schemas import (
    LoginResponse,
    UserLoginRequest,
    UserPublic,
    UserRegistrationRequest,
)
from app.domains.identity.service import (
    authenticate_user,
    register_user,
)
from app.domains.identity.sessions import (
    create_session,
    get_user_by_session_token,
    revoke_session,
)
from app.domains.security.service import record_audit_event



router = APIRouter(
    prefix="/auth",
    tags=["identity"],
)


@router.post(
    "/register",
    response_model=UserPublic,
    status_code=status.HTTP_201_CREATED,
)
def register(
    payload: UserRegistrationRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> UserPublic:
    """Register a new user account."""

    try:
        user = register_user(db, payload)

    except ValueError as exc:
        record_audit_event(
            db,
            event_type="USER_REGISTRATION_FAILED",
            result="failure",
            email=payload.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc

    record_audit_event(
        db,
        event_type="USER_REGISTERED",
        result="success",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return UserPublic.model_validate(user)


@router.post(
    "/login",
    response_model=LoginResponse,
)

def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    """Authenticate a user and create a server-managed session."""

    user = authenticate_user(
        db,
        payload,
    )

    if user is None:
        ip_address = (
            request.client.host
            if request.client
            else None
        )

        record_audit_event(
            db,
            event_type="LOGIN_FAILED",
            result="failure",
            email=payload.email,
            ip_address=ip_address,
            user_agent=request.headers.get("user-agent"),
        )

        detect_repeated_login_failures(
            db,
            payload.email,
        )

        detect_password_spray(
            db,
            ip_address,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    _, raw_session_token = create_session(
        db,
        user.id,
    )

    success_event = record_audit_event(
        db,
        event_type="LOGIN_SUCCESS",
        result="success",
        user_id=user.id,
        email=user.email,
        ip_address=(
            request.client.host
            if request.client
            else None
        ),
        user_agent=request.headers.get(
            "user-agent"
        ),
    )

    detect_success_after_failures(
        db,
        email=user.email,
        success_event_id=success_event.id,
    )

    response.set_cookie(
    key=settings.SESSION_COOKIE_NAME,
    value=raw_session_token,
    httponly=True,
    secure=settings.session_cookie_secure,
    samesite=settings.SESSION_COOKIE_SAMESITE,
    max_age=(
        60
        * 60
        * settings.SESSION_TTL_HOURS
    ),
)

    return LoginResponse(
        message="Authentication successful.",
        user=UserPublic.model_validate(
            user
        ),
    )


@router.get(
    "/me",
    response_model=UserPublic,
)
def get_current_user(
    current_user: User = Depends(require_current_user),
) -> UserPublic:
    """Return the currently authenticated user."""

    return UserPublic.model_validate(current_user)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
)
def logout(
    request: Request,
    response: Response,
    titan_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> Response:
    """Revoke the current session and remove its browser cookie."""

    user = None

    if titan_session is not None:
        user = get_user_by_session_token(
            db,
            titan_session,
        )

        revoke_session(
            db,
            titan_session,
        )

    record_audit_event(
        db,
        event_type="LOGOUT",
        result="success",
        user_id=user.id if user else None,
        email=user.email if user else None,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    response.delete_cookie(
    key=settings.SESSION_COOKIE_NAME,
    httponly=True,
    secure=settings.session_cookie_secure,
    samesite=settings.SESSION_COOKIE_SAMESITE,
)

    response.status_code = status.HTTP_204_NO_CONTENT

    return response