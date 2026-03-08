"""dspy-kya — KYA (Know Your Agent) identity verification for DSPy modules.

Provides functions, decorators, and helpers to bring cryptographic agent identity
to DSPy workflows. No blockchain, no cloud dependency — just Ed25519 signatures.

Usage:
    from dspy_kya import create_module_card, attach_card, kya_verify_identity, kya_trust_gate, kya_verified
"""

__version__ = "0.1.0"

from dspy_kya.card import create_module_card, attach_card, get_card
from dspy_kya.identity import kya_verify_identity
from dspy_kya.trust_gate import kya_trust_gate
from dspy_kya.middleware import kya_verified, KYAVerificationError

__all__ = [
    "create_module_card",
    "attach_card",
    "get_card",
    "kya_verify_identity",
    "kya_trust_gate",
    "kya_verified",
    "KYAVerificationError",
]
