"""
Sovereign Shield — Complete AI Security Framework
Extracted from the KAIROS Autonomous Intelligence System.

Components:
    CoreSafety      — Immutable security laws, hash integrity, action auditing
    Conscience      — Ethical evaluation, deception/harm detection
    InputFilter     — Input sanitization, injection blocking, gibberish detection
    Firewall        — Identity gating, rate limiting, DDoS protection
    AdaptiveShield  — Self-improving security filter, learns from missed attacks
    TruthGuard      — Factual hallucination detection, verified fact caching
    ActionParser    — Deterministic LLM output parser (SUBCONSCIOUS/ACTION format)
    LoRAExporter    — Training data compiler for Truth Adapter fine-tuning
"""

from .core import CoreSafety, FrozenNamespace
from .conscience import Conscience
from .input_filter import InputFilter
from .firewall import Firewall
from .adaptive import AdaptiveShield
from .truth_guard import TruthGuard
from .action_parser import ActionParser
from .lora_export import LoRAExporter

__all__ = [
    "CoreSafety",
    "FrozenNamespace",
    "Conscience",
    "InputFilter",
    "Firewall",
    "AdaptiveShield",
    "TruthGuard",
    "ActionParser",
    "LoRAExporter",
]

__version__ = "1.2.0"
