import hashlib
import hmac

from fastapi import HTTPException, Request, status

from app.core.config import settings


def create_csrf_token(
    session_token: str,
) -> str:
    """
    Create a CSRF token cryptographically bound to
    the authenticated session token.

    The raw session token is never exposed to JavaScript.
    """

    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        session_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def validate_csrf_token(
    *,
    session_token: str,
    csrf_token: str,
) -> bool:
    """
    Verify that a CSRF token belongs to the supplied
    authenticated session.
    """

    expected_token = create_csrf_token(
        session_token
    )

    return hmac.compare_digest(
        csrf_token,
        expected_token,
    )


def require_csrf_token(
    request: Request,
) -> None:
    """
    Require a valid double-submit CSRF token.

    A browser must provide the same CSRF value in:
      1. the CSRF cookie
      2. the X-CSRF-Token header

    Titan then verifies that the token is cryptographically
    bound to the current session.
    """

    session_token = request.cookies.get(
        settings.SESSION_COOKIE_NAME
    )

    csrf_cookie = request.cookies.get(
        settings.CSRF_COOKIE_NAME
    )

    csrf_header = request.headers.get(
        settings.CSRF_HEADER_NAME
    )

    if (
        session_token is None
        or csrf_cookie is None
        or csrf_header is None
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )

    if not hmac.compare_digest(
        csrf_cookie,
        csrf_header,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )

    if not validate_csrf_token(
        session_token=session_token,
        csrf_token=csrf_cookie,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF validation failed.",
        )