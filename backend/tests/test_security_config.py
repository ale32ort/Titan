import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_development_cookie_does_not_require_https():
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="development",
        DEBUG=True,
        SECRET_KEY="CHANGE_ME",
        SENSOR_INGEST_API_KEY="CHANGE_ME",
    )

    assert settings.session_cookie_secure is False


def test_production_cookie_requires_https():
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        DEBUG=False,
        SECRET_KEY=(
            "production-test-secret-"
            "not-used-outside-pytest"
        ),
        SENSOR_INGEST_API_KEY=(
            "production-sensor-key-"
            "not-used-outside-pytest"
        ),
    )

    assert settings.session_cookie_secure is True


def test_production_rejects_placeholder_secret():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY="CHANGE_ME",
            SENSOR_INGEST_API_KEY=(
                "production-sensor-key-"
                "not-used-outside-pytest"
            ),
        )


def test_production_rejects_debug_mode():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DEBUG=True,
            SECRET_KEY=(
                "production-test-secret-"
                "not-used-outside-pytest"
            ),
            SENSOR_INGEST_API_KEY=(
                "production-sensor-key-"
                "not-used-outside-pytest"
            ),
        )


def test_production_rejects_placeholder_sensor_key():
    with pytest.raises(
        ValidationError
    ):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DEBUG=False,
            SECRET_KEY=(
                "production-test-secret-"
                "not-used-outside-pytest"
            ),
            SENSOR_INGEST_API_KEY="CHANGE_ME",
        )