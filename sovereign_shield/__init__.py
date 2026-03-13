"""
Sovereign Shield — Complete AI Security Framework
Extracted from the KAIROS Autonomous Intelligence System.

Components:
    CoreSafety        — Immutable security laws, hash integrity, action auditing
    Conscience        — Ethical evaluation, deception/harm detection
    InputFilter       — Input sanitization, injection blocking, gibberish detection
    Firewall          — Identity gating, rate limiting, DDoS protection
    AdaptiveShield    — Self-improving security filter, learns from missed attacks
    TruthGuard        — Factual hallucination detection, verified fact caching
    ActionParser      — Deterministic LLM output parser (SUBCONSCIOUS/ACTION format)
    LoRAExporter      — Training data compiler for Truth Adapter fine-tuning
    HITLApproval      — Human-in-the-loop approval workflow (AISVS C9.2, C14.2)
    SIEMLogger        — Structured security event logger for SIEM integration (AISVS C13.2.2)
    MultiModalFilter  — Multi-modal input validation (AISVS C2.7)
"""

from .core import CoreSafety, FrozenNamespace
from .conscience import Conscience
from .input_filter import InputFilter
from .firewall import Firewall
from .adaptive import AdaptiveShield
from .truth_guard import TruthGuard
from .action_parser import ActionParser
from .lora_export import LoRAExporter
from .hitl import HITLApproval, ApprovalStatus
from .siem_logger import SIEMLogger
from .multimodal_filter import MultiModalFilter

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
    "HITLApproval",
    "ApprovalStatus",
    "SIEMLogger",
    "MultiModalFilter",
]

__version__ = "1.2.1"
