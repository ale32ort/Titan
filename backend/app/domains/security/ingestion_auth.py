import hmac

from fastapi import (
    HTTPException,
    Request,
    status,
)

from app.core.config import settings


def require_sensor_api_key(
    request: Request,
) -> None:
    """
    Authenticate machine-to-machine sensor ingestion.

    Sensors do not use Titan's browser session or
    analyst RBAC. They authenticate with a dedicated
    machine credential.
    """

    supplied_key = request.headers.get(
        settings.SENSOR_INGEST_HEADER_NAME
    )

    expected_key = (
        settings.SENSOR_INGEST_API_KEY
    )

    if (
        supplied_key is None
        or not hmac.compare_digest(
            supplied_key,
            expected_key,
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid sensor credentials.",
        )