"""
Sovereign Shield — Production-grade AI defense with deterministic + LLM veto verification.

Usage:
    from sovereign_shield import VetoShield
    from sovereign_shield.providers import GeminiProvider

    shield = VetoShield(provider=GeminiProvider(api_key="..."))
    result = shield.scan("user input here")
"""

from sovereign_shield.veto import VetoShield

__all__ = ["VetoShield"]
__version__ = "2.0.0"
