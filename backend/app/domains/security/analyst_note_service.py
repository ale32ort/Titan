from sqlalchemy import select
from sqlalchemy.orm import Session

from app.domains.security.analyst_notes import AnalystNote


def create_analyst_note(
    db: Session,
    *,
    finding_id: str,
    author_user_id: str,
    content: str,
) -> AnalystNote:
    note = AnalystNote(
        finding_id=finding_id,
        author_user_id=author_user_id,
        content=content,
    )

    db.add(note)
    db.commit()
    db.refresh(note)

    return note


def get_analyst_notes_for_finding(
    db: Session,
    *,
    finding_id: str,
) -> list[AnalystNote]:
    statement = (
        select(AnalystNote)
        .where(
            AnalystNote.finding_id == finding_id
        )
        .order_by(
            AnalystNote.created_at.desc()
        )
    )

    return list(
        db.scalars(statement).all()
    )