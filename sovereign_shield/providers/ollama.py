"""
Ollama provider for VetoShield.

No extra dependencies — uses stdlib requests to localhost.
Fully offline, zero cost.
"""

import json
import urllib.request
import urllib.error

from sovereign_shield.providers.base import LLMProvider
from sovereign_shield.prompts import VERIFICATION_PROMPT


class OllamaProvider(LLMProvider):
    """Uses a local Ollama model for attack verification. Zero cost, fully offline."""

    def __init__(
        self,
        model: str = "llama3.1:8b",
        host: str = "http://localhost:11434",
    ):
        self._model = model
        self._host = host.rstrip("/")

    def verify(self, text: str) -> str:
        prompt = VERIFICATION_PROMPT.format(text=text)

        payload = json.dumps({
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
                "num_predict": 10,
            },
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self._host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "").strip()
        except urllib.error.URLError as e:
            raise ConnectionError(
                f"Cannot connect to Ollama at {self._host}. "
                f"Is Ollama running? Error: {e}"
            )

    @property
    def name(self) -> str:
        return f"Ollama({self._model})"
