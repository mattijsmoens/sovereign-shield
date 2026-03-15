"""
Abstract base class for LLM providers.

Any LLM can be used as a veto checker by implementing this interface.
"""

from abc import ABC, abstractmethod


class LLMProvider(ABC):
    """Base class for LLM verification providers."""

    @abstractmethod
    def verify(self, text: str) -> str:
        """
        Send user input to the LLM for attack classification.

        Args:
            text: The user input to classify.

        Returns:
            Raw LLM response string. VetoShield handles parsing/validation.
        """
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__
