from fastapi import APIRouter

from app.domains.organization.models import Organization


router = APIRouter(
    prefix="/organizations",
    tags=["organizations"],
)


@router.get("/current", response_model=Organization)
def get_current_organization() -> Organization:
    """Return the current organization managed by Titan."""
    return Organization(
        name="Titan Intelligence",
        mission=(
            "Help leaders make better decisions through trusted "
            "organizational intelligence."
        ),
        vision=(
            "Become the intelligence layer organizations rely on "
            "for important decisions."
        ),
        industry="Enterprise Software",
    )