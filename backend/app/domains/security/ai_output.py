from typing import Literal

from pydantic import BaseModel, Field


class AITriageOutput(BaseModel):
    executive_summary: str = Field(
        min_length=1,
        max_length=1000,
    )

    analyst_assessment: str = Field(
        min_length=1,
        max_length=2000,
    )

    confirmed_facts: list[str]

    hypotheses: list[str]

    missing_context: list[str]

    recommended_actions: list[str]

    confidence: Literal[
        "low",
        "medium",
        "high",
    ]

    compromise_status: Literal[
        "not_established",
        "suspected",
        "confirmed",
    ]