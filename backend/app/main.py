import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.logging import configure_logging
from app.domains.identity.router import router as identity_router
from app.domains.security.router import router as security_router


def create_app() -> FastAPI:
    """Create and configure the Titan Security Operations application."""

    configure_logging()
    logger = logging.getLogger("titan.api")

    application = FastAPI(
        title=settings.APP_NAME,
        description=(
            "Backend API for Titan Security Operations, an evidence-driven, "
            "AI-assisted security operations and investigation platform."
        ),
        version=settings.APP_VERSION,
        debug=settings.DEBUG,
    )

    application.include_router(
        identity_router,
        prefix=settings.API_PREFIX,
    )

    application.include_router(
        security_router,
        prefix="/api/v1",
    )

    @application.get("/", tags=["system"])
    def root() -> dict[str, str]:
        logger.info("Root endpoint requested")

        return {
            "message": f"Welcome to {settings.APP_NAME}",
            "product": "Titan Security Operations",
            "version": settings.APP_VERSION,
        }

    @application.get(
        f"{settings.API_PREFIX}/health",
        tags=["system"],
    )
    def health_check() -> dict[str, str]:
        logger.info("Health check requested")

        return {
            "status": "healthy",
            "service": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
        }

    logger.info(
        "Application configured | service=%s | version=%s | environment=%s",
        settings.APP_NAME,
        settings.APP_VERSION,
        settings.ENVIRONMENT,
    )

    return application


app = create_app()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)