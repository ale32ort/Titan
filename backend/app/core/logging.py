import logging
import sys

from app.core.config import settings


def configure_logging() -> None:
    """Configure application-wide logging."""

    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
        format=(
            "%(asctime)s | %(levelname)s | "
            "%(name)s | %(message)s"
        ),
        handlers=[logging.StreamHandler(sys.stdout)],
        force=True,
    )