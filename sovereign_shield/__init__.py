"""
Sovereign Shield — Standalone AI Security Framework
Extracted from the KAIROS Autonomous Intelligence System.

Components:
    CoreSafety      — Immutable security laws, hash integrity, action auditing
    Conscience      — Ethical evaluation, deception/harm detection
    InputFilter     — Input sanitization, injection blocking, gibberish detection
    Firewall        — Identity gating, rate limiting, DDoS protection
    AdaptiveShield  — Self-improving security filter, learns from missed attacks
"""

from .core import CoreSafety, FrozenNamespace
from .conscience import Conscience
from .input_filter import InputFilter
from .firewall import Firewall
from .adaptive import AdaptiveShield

__all__ = [
    "CoreSafety",
    "FrozenNamespace",
    "Conscience",
    "InputFilter",
    "Firewall",
    "AdaptiveShield",
]

__version__ = "1.0.4"
