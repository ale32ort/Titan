from abc import ABC, abstractmethod

from app.domains.security.ai_output import (
    AITriageOutput,
)
from app.domains.security.ai_prompt import (
    AIPrompt,
)


class AIProviderError(RuntimeError):
    """
    Base exception for failures involving
    an external AI provider.
    """


class AIProviderTemporaryError(
    AIProviderError
):
    """
    A transient provider failure that may
    succeed if attempted again later.
    """


class AIProviderPermanentError(
    AIProviderError
):
    """
    A non-transient provider/configuration
    failure that should not be blindly retried.
    """


class AIProviderTimeoutError(
    AIProviderTemporaryError
):
    """
    Provider request exceeded Titan's
    configured timeout.
    """


class AIClient(ABC):
    """
    Interface that every Titan AI provider
    must implement.
    """

    @abstractmethod
    def analyze_security_finding(
        self,
        prompt: AIPrompt,
    ) -> AITriageOutput:
        """
        Analyze a security finding and return
        validated structured triage output.
        """
        raise NotImplementedError