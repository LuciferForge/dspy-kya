"""Card helpers — create and manage KYA identity cards for DSPy modules.

Works with or without dspy installed. When dspy is available, cards
are stored on module objects via a _kya_card attribute.

DSPy modules expose named_predictors() and parameters() for introspection.
Each predictor uses a Signature with input/output fields.
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional


def _resolve_module_fields(module: Any) -> Dict[str, Any]:
    """Extract identity-relevant fields from a DSPy Module object.

    DSPy Module has: named_predictors(), parameters(), forward().
    We map these to KYA card fields.
    """
    class_name = type(module).__name__
    slug = class_name.lower().replace(" ", "-").replace("_", "-")
    slug = "".join(c for c in slug if c.isalnum() or c == "-")
    slug = slug.strip("-") or "module"

    # Extract predictors
    predictors: List[Dict[str, str]] = []
    if hasattr(module, "named_predictors"):
        for name, predictor in module.named_predictors():
            sig = getattr(predictor, "signature", "")
            predictors.append({
                "name": name,
                "signature": str(sig),
                "type": type(predictor).__name__,
            })

    # Extract signature fields from predictors
    input_fields: List[str] = []
    output_fields: List[str] = []
    for _name, predictor in (module.named_predictors() if hasattr(module, "named_predictors") else []):
        sig = getattr(predictor, "signature", None)
        if sig and hasattr(sig, "input_fields"):
            input_fields.extend(sig.input_fields)
        if sig and hasattr(sig, "output_fields"):
            output_fields.extend(sig.output_fields)

    return {
        "class_name": class_name,
        "slug": slug,
        "predictors": predictors,
        "input_fields": list(set(input_fields)),
        "output_fields": list(set(output_fields)),
        "has_forward": hasattr(module, "forward") and callable(getattr(module, "forward")),
    }


def _extract_predictor_capabilities(module: Any) -> List[Dict[str, str]]:
    """Extract capabilities from DSPy module's predictors."""
    capabilities = []
    if hasattr(module, "named_predictors"):
        for name, predictor in module.named_predictors():
            sig_str = str(getattr(predictor, "signature", ""))
            predictor_type = type(predictor).__name__
            capabilities.append({
                "name": name,
                "description": f"{predictor_type}: {sig_str}"[:200],
                "risk_level": "medium",
                "scope": "as-configured",
            })
    return capabilities


def create_module_card(
    module: Any,
    *,
    owner_name: str = "unspecified",
    owner_contact: str = "unspecified",
    agent_id_prefix: str = "dspy",
    capabilities: Optional[List[Dict[str, str]]] = None,
    version: str = "0.1.0",
    risk_classification: str = "minimal",
    human_oversight: str = "human-on-the-loop",
    purpose: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a KYA identity card from a DSPy Module.

    Args:
        module: A dspy.Module instance (or any object with named_predictors()/forward()).
        owner_name: Organization or person responsible for this module.
        owner_contact: Contact email for security/compliance inquiries.
        agent_id_prefix: Prefix for the agent_id (default: "dspy").
        capabilities: Override auto-detected capabilities. If None, extracted from predictors.
        version: Semantic version for the module.
        risk_classification: EU AI Act risk level (minimal/limited/high/unacceptable).
        human_oversight: Oversight level (none/human-on-the-loop/human-in-the-loop/human-above-the-loop).
        purpose: Custom purpose string. If None, auto-generated from module structure.

    Returns:
        A KYA card dict conforming to the v0.1 schema.
    """
    fields = _resolve_module_fields(module)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if capabilities is None:
        capabilities = _extract_predictor_capabilities(module)

    # Build purpose from module structure
    if purpose is None:
        predictor_names = [p["name"] for p in fields["predictors"]]
        if predictor_names:
            purpose = f"DSPy module '{fields['class_name']}' with predictors: {', '.join(predictor_names)}"
        else:
            purpose = f"DSPy module '{fields['class_name']}'"
        if fields["input_fields"]:
            purpose += f". Inputs: {', '.join(fields['input_fields'])}"
        if fields["output_fields"]:
            purpose += f". Outputs: {', '.join(fields['output_fields'])}"

    # Ensure purpose meets KYA minLength of 10
    if len(purpose) < 10:
        purpose = f"DSPy module performing the role of {fields['class_name']}"
    # Cap at schema maxLength
    purpose = purpose[:500]

    card: Dict[str, Any] = {
        "kya_version": "0.1",
        "agent_id": f"{agent_id_prefix}/{fields['slug']}",
        "name": fields["class_name"],
        "version": version,
        "purpose": purpose,
        "agent_type": "autonomous",
        "owner": {
            "name": owner_name,
            "contact": owner_contact,
        },
        "capabilities": {
            "declared": capabilities,
            "denied": [],
        },
        "data_access": {
            "sources": [],
            "destinations": [],
            "pii_handling": "none",
            "retention_policy": "session-only",
        },
        "security": {
            "last_audit": None,
            "known_vulnerabilities": [],
            "injection_tested": False,
        },
        "compliance": {
            "frameworks": [],
            "risk_classification": risk_classification,
            "human_oversight": human_oversight,
        },
        "behavior": {
            "logging_enabled": False,
            "log_format": "none",
            "max_actions_per_minute": 0,
            "kill_switch": True,
            "escalation_policy": "halt-and-notify",
        },
        "metadata": {
            "created_at": now,
            "updated_at": now,
            "tags": ["dspy"],
            "predictors": fields["predictors"],
            "input_fields": fields["input_fields"],
            "output_fields": fields["output_fields"],
        },
    }

    return card


def attach_card(module: Any, card: Dict[str, Any]) -> None:
    """Attach a KYA identity card to a DSPy Module instance.

    Stores the card as module._kya_card for retrieval by tools and middleware.
    """
    module._kya_card = card


def get_card(module: Any) -> Optional[Dict[str, Any]]:
    """Retrieve the KYA card attached to a DSPy Module, if any."""
    return getattr(module, "_kya_card", None)
