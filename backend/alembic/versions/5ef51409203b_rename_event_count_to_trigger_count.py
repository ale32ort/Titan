"""rename event count to trigger count

Revision ID: 5ef51409203b
Revises: 333fbab4d48a
Create Date: 2026-08-13 18:45:07.518865

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "5ef51409203b"
down_revision: Union[str, Sequence[str], None] = "333fbab4d48a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.alter_column(
        "security_findings",
        "event_count",
        new_column_name="trigger_count",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column(
        "security_findings",
        "trigger_count",
        new_column_name="event_count",
    )