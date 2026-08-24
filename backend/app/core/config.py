from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
)


class Settings(BaseSettings):
    """Global application configuration."""

    APP_NAME: str = "Project Titan API"
    APP_VERSION: str = "0.1.0"

    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    API_PREFIX: str = "/api/v1"
    LOG_LEVEL: str = "INFO"

    TRUSTED_PROXY_IPS: str = ""

    SECRET_KEY: str = "CHANGE_ME"

    DATABASE_URL: str = (
        "postgresql+psycopg://"
        "titan:titan@localhost:5432/titan"
    )

    ANTHROPIC_API_KEY: str | None = None
    ANTHROPIC_MODEL: str = "claude-sonnet-5"

    SESSION_TTL_HOURS: int = 12
    SESSION_COOKIE_NAME: str = "titan_session"
    SESSION_COOKIE_SAMESITE: str = "lax"

    CSRF_COOKIE_NAME: str = "titan_csrf"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    @property
    def is_production(self) -> bool:
        return (
            self.ENVIRONMENT.strip().lower()
            == "production"
        )

    @property
    def session_cookie_secure(self) -> bool:
        """
        Secure cookies must be enabled in production.

        Local development currently uses HTTP, so Secure
        remains false outside production.
        """
        return self.is_production

    @model_validator(mode="after")
    def validate_security_configuration(
        self,
    ) -> "Settings":
        """
        Refuse obviously unsafe configuration in production.
        """

        if not self.is_production:
            return self

        unsafe_secrets = {
            "",
            "CHANGE_ME",
            "replace_with_secure_secret",
        }

        if self.SECRET_KEY.strip() in unsafe_secrets:
            raise ValueError(
                "Production requires a secure SECRET_KEY."
            )

        if self.DEBUG:
            raise ValueError(
                "DEBUG must be disabled in production."
            )

        return self


@lru_cache
def get_settings() -> Settings:
    """Return the cached application settings."""

    return Settings()


settings = get_settings()