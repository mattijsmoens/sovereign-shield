"""
Sovereign Shield — Production-grade AI defense suite.

Deterministic pre-execution security for autonomous AI systems.
Zero external dependencies. Pure Python stdlib.

Usage:
    from sovereign_shield import VetoShield, CoreSafety, Conscience
    from sovereign_shield.providers import GeminiProvider

    # Full two-tier defense (deterministic + LLM veto)
    shield = VetoShield(provider=GeminiProvider(api_key="..."))
    result = shield.scan("user input here")

    # Deterministic-only
    from sovereign_shield import InputFilter, Firewall
    f = InputFilter()
    is_safe, result = f.process("user input")
"""

from sovereign_shield.veto import VetoShield
from sovereign_shield.core_safety import CoreSafety, FrozenNamespace
from sovereign_shield.conscience import Conscience
from sovereign_shield.input_filter import InputFilter
from sovereign_shield.firewall import Firewall
from sovereign_shield.adaptive import AdaptiveShield
from sovereign_shield.siem_logger import SIEMLogger
from sovereign_shield.hitl import HITLApproval, ApprovalStatus
from sovereign_shield.multimodal_filter import MultiModalFilter
from sovereign_shield.truth_guard import TruthGuard

__all__ = [
    "VetoShield",
    "CoreSafety",
    "FrozenNamespace",
    "Conscience",
    "InputFilter",
    "Firewall",
    "AdaptiveShield",
    "SIEMLogger",
    "HITLApproval",
    "ApprovalStatus",
    "MultiModalFilter",
    "TruthGuard",
]
__version__ = "2.2.3"
