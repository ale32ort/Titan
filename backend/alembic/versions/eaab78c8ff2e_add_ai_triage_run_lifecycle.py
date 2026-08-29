"""add ai triage run lifecycle

Revision ID: eaab78c8ff2e
Revises: fb0be8dac9bb
Create Date: 2026-08-28 20:19:37.693248

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "eaab78c8ff2e"
down_revision: Union[
    str,
    Sequence[str],
    None,
] = "fb0be8dac9bb"

branch_labels: Union[
    str,
    Sequence[str],
    None,
] = None

depends_on: Union[
    str,
    Sequence[str],
    None,
] = None


def upgrade() -> None:
    """
    Add lifecycle state to AI triage runs.

    Existing records predate lifecycle tracking
    and represent successful triage runs, so they
    are backfilled as completed.
    """

    op.add_column(
        "ai_triage_runs",
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="completed",
        ),
    )

    op.add_column(
        "ai_triage_runs",
        sa.Column(
            "error_type",
            sa.String(length=100),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_triage_runs",
        sa.Column(
            "error_message",
            sa.Text(),
            nullable=True,
        ),
    )

    op.add_column(
        "ai_triage_runs",
        sa.Column(
            "completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )

    # Historical records were only written after
    # successful AI completion, so created_at is
    # the best available completion timestamp.
    op.execute(
        """
        UPDATE ai_triage_runs
        SET completed_at = created_at
        WHERE completed_at IS NULL
        """
    )

    op.alter_column(
        "ai_triage_runs",
        "executive_summary",
        existing_type=sa.TEXT(),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "analyst_assessment",
        existing_type=sa.TEXT(),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "confirmed_facts",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "hypotheses",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "missing_context",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "recommended_actions",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "confidence",
        existing_type=sa.VARCHAR(
            length=20
        ),
        nullable=True,
    )

    op.alter_column(
        "ai_triage_runs",
        "compromise_status",
        existing_type=sa.VARCHAR(
            length=30
        ),
        nullable=True,
    )

    op.create_index(
        op.f(
            "ix_ai_triage_runs_status"
        ),
        "ai_triage_runs",
        ["status"],
        unique=False,
    )

    # Existing rows have now been backfilled.
    # New application code explicitly supplies
    # running/completed/failed status.
    op.alter_column(
        "ai_triage_runs",
        "status",
        server_default=None,
    )


def downgrade() -> None:
    """
    Remove AI triage lifecycle fields.

    Downgrade assumes no failed/running records
    with NULL result fields need to be preserved.
    """

    op.drop_index(
        op.f(
            "ix_ai_triage_runs_status"
        ),
        table_name="ai_triage_runs",
    )

    # Only completed records satisfy the old
    # schema's requirement that AI output exists.
    op.execute(
        """
        DELETE FROM ai_triage_runs
        WHERE status <> 'completed'
        """
    )

    op.alter_column(
        "ai_triage_runs",
        "compromise_status",
        existing_type=sa.VARCHAR(
            length=30
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "confidence",
        existing_type=sa.VARCHAR(
            length=20
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "recommended_actions",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "missing_context",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "hypotheses",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "confirmed_facts",
        existing_type=postgresql.JSON(
            astext_type=sa.Text()
        ),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "analyst_assessment",
        existing_type=sa.TEXT(),
        nullable=False,
    )

    op.alter_column(
        "ai_triage_runs",
        "executive_summary",
        existing_type=sa.TEXT(),
        nullable=False,
    )

    op.drop_column(
        "ai_triage_runs",
        "completed_at",
    )

    op.drop_column(
        "ai_triage_runs",
        "error_message",
    )

    op.drop_column(
        "ai_triage_runs",
        "error_type",
    )

    op.drop_column(
        "ai_triage_runs",
        "status",
    )
