from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Entity(BaseModel):
    """The base object for everything Titan understands."""

    id: UUID = Field(default_factory=uuid4)

    name: str = Field(
        min_length=1,
        max_length=200,
        description="Human-readable name of the entity."
    )

    entity_type: str = Field(
        description="The kind of entity (Organization, Person, Project, etc.)"
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )