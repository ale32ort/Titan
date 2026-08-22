from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Organization(BaseModel):
    """A structured system working toward a shared mission."""

    id: UUID = Field(default_factory=uuid4)

    name: str = Field(
        min_length=1,
        max_length=200,
        description="The organization's official name.",
    )

    mission: str = Field(
        min_length=1,
        max_length=1000,
        description="The shared purpose the organization exists to serve.",
    )

    vision: str | None = Field(
        default=None,
        max_length=1000,
        description="The future state the organization is working toward.",
    )

    industry: str | None = Field(
        default=None,
        max_length=200,
        description="The primary field or sector in which the organization operates.",
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )