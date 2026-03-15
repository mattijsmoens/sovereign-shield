"""
Google Gemini provider for VetoShield.

Uses the google-genai SDK (>= 1.0).
Install: pip install google-genai

Rate limit strategy:
  - Client-side rate limiter: 15 RPM max (configurable)
  - Hard 15s timeout per request via ThreadPoolExecutor
  - 3 retries with exponential backoff on 429 / timeout
  - After all retries exhausted → VetoShield fail-closed blocks it
"""

import time
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from sovereign_shield.providers.base import LLMProvider
from sovereign_shield.prompts import VERIFICATION_PROMPT

logger = logging.getLogger("sovereign_shield.gemini")

_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="gemini")


class GeminiProvider(LLMProvider):
    """Uses Google Gemini for attack verification with built-in rate limiting."""

    def __init__(self, api_key: str, model: str = "gemini-2.0-flash",
                 rpm: int = 15):
        """
        Args:
            api_key: Gemini API key
            model: Model name (default: gemini-2.0-flash)
            rpm: Requests per minute limit (default: 15)
        """
        try:
            from google import genai
        except ImportError:
            raise ImportError(
                "google-genai is required for GeminiProvider. "
                "Install with: pip install google-genai"
            )

        self._client = genai.Client(api_key=api_key)
        self._model_name = model
        self._max_retries = 3
        self._base_delay = 2.0
        self._timeout = 15  # hard timeout in seconds

        # Rate limiter: track call timestamps
        self._rpm = rpm
        self._min_interval = 60.0 / rpm  # seconds between calls
        self._last_call = 0.0
        self._rate_lock = threading.Lock()

    def _wait_for_rate_limit(self):
        """Block until we're allowed to make the next call."""
        with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                wait = self._min_interval - elapsed
                time.sleep(wait)
            self._last_call = time.monotonic()

    def _call_api(self, prompt: str) -> str:
        """Make the actual API call (runs in thread for timeout control)."""
        response = self._client.models.generate_content(
            model=self._model_name,
            contents=prompt,
            config={
                "temperature": 0.0,
                "max_output_tokens": 10,
            },
        )
        return response.text.strip()

    def verify(self, text: str) -> str:
        prompt = VERIFICATION_PROMPT.format(text=text)

        last_error = None
        for attempt in range(self._max_retries + 1):
            # Respect rate limit before each attempt
            self._wait_for_rate_limit()

            try:
                future = _executor.submit(self._call_api, prompt)
                return future.result(timeout=self._timeout)

            except FuturesTimeout:
                last_error = TimeoutError(
                    f"Gemini timed out after {self._timeout}s "
                    f"(attempt {attempt + 1}/{self._max_retries + 1})"
                )
                future.cancel()
                logger.warning(str(last_error))

                if attempt < self._max_retries:
                    delay = self._base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                raise last_error

            except Exception as e:
                last_error = e
                err_str = str(e).lower()
                is_rate_limit = (
                    "429" in err_str
                    or "resource_exhausted" in err_str
                    or "rate" in err_str
                    or "quota" in err_str
                )

                if is_rate_limit and attempt < self._max_retries:
                    delay = self._base_delay * (2 ** attempt)
                    logger.warning(
                        f"Rate limited (attempt {attempt + 1}/{self._max_retries}), "
                        f"retrying in {delay:.0f}s..."
                    )
                    time.sleep(delay)
                    continue

                raise

        raise last_error

    @property
    def name(self) -> str:
        return f"Gemini({self._model_name})"
