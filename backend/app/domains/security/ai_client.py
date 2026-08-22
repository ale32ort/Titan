from abc import ABC, abstractmethod

from app.domains.security.ai_output import AITriageOutput
from app.domains.security.ai_prompt import AIPrompt


class AIClient(ABC):
    """Interface that every Titan AI provider must implement."""

    @abstractmethod
    def analyze_security_finding(
        self,
        prompt: AIPrompt,
    ) -> AITriageOutput:
        """Analyze a security finding and return validated triage output."""
        raise NotImplementedError