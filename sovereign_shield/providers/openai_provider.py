"""
OpenAI / compatible API provider for VetoShield.

Install: pip install sovereign-shield[openai]
Works with any OpenAI-compatible API (OpenAI, Azure, Together, etc.)
"""

from typing import Optional

from sovereign_shield.providers.base import LLMProvider
from sovereign_shield.prompts import VERIFICATION_PROMPT


class OpenAIProvider(LLMProvider):
    """Uses OpenAI or any compatible API for attack verification."""

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o-mini",
        base_url: Optional[str] = None,
    ):
        try:
            from openai import OpenAI
        except ImportError:
            raise ImportError(
                "openai is required for OpenAIProvider. "
                "Install with: pip install sovereign-shield[openai]"
            )

        self._client = OpenAI(api_key=api_key, base_url=base_url)
        self._model = model

    def verify(self, text: str) -> str:
        prompt = VERIFICATION_PROMPT.format(text=text)
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=10,
        )
        return response.choices[0].message.content.strip()

    @property
    def name(self) -> str:
        return f"OpenAI({self._model})"
