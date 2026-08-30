from app.core.config import settings


def test_pytest_uses_test_only_configuration():
    assert settings.ENVIRONMENT == "test"

    assert (
        settings.SECRET_KEY
        == "pytest-secret-key-not-for-production"
    )

    assert (
        settings.SENSOR_INGEST_API_KEY
        == "pytest-sensor-key"
    )

    assert (
        settings.DATABASE_URL
        == "sqlite+pysqlite:///:memory:"
    )

    assert settings.ANTHROPIC_API_KEY in {
        "",
        None,
    }