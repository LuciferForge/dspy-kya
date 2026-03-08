"""Middleware — @kya_verified decorator for gating DSPy module execution.

Wraps a DSPy module's forward() method or any callable to require KYA
identity verification before the function body executes.
"""

from __future__ import annotations

import functools
import json
from typing import Any, Callable, Optional

from dspy_kya.card import get_card
from dspy_kya.identity import _verify_card_data


class KYAVerificationError(Exception):
    """Raised when a module fails KYA identity verification."""

    def __init__(self, module_name: str, reason: str):
        self.module_name = module_name
        self.reason = reason
        super().__init__(f"KYA verification failed for '{module_name}': {reason}")


def kya_verified(
    min_score: int = 0,
    require_signature: bool = False,
    required_capabilities: Optional[list[str]] = None,
    on_fail: str = "raise",
) -> Callable:
    """Decorator that gates a function on KYA identity verification.

    The decorated function must receive a `module` keyword argument
    (or first positional argument) that has a _kya_card attached via
    `attach_card()`.

    Can also be used to wrap a DSPy Module class, gating its forward() method.

    Args:
        min_score: Minimum completeness score (0-100). Default 0 (any valid card).
        require_signature: Require a verified Ed25519 signature.
        required_capabilities: List of predictor/capability names the module must declare.
        on_fail: What to do on failure. "raise" (default) raises KYAVerificationError.
                 "skip" returns None silently. "log" prints a warning and continues.

    Usage:
        @kya_verified(min_score=50)
        def run_pipeline(module, query):
            return module(query=query)

        # Or wrap a module class:
        @kya_verified(min_score=50)
        class MyModule(dspy.Module):
            def forward(self, query):
                ...
    """

    def decorator(func_or_class: Any) -> Any:
        # If decorating a class, wrap its forward() method
        if isinstance(func_or_class, type):
            original_forward = func_or_class.forward

            @functools.wraps(original_forward)
            def wrapped_forward(self_module: Any, *args: Any, **kwargs: Any) -> Any:
                return _check_and_run(
                    self_module, original_forward, (self_module, *args), kwargs,
                    min_score, require_signature, required_capabilities, on_fail,
                )

            func_or_class.forward = wrapped_forward
            return func_or_class

        # Otherwise, decorating a function
        @functools.wraps(func_or_class)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Try to find the module from args
            module = kwargs.get("module")
            if module is None and args:
                candidate = args[0]
                if hasattr(candidate, "named_predictors") or hasattr(candidate, "_kya_card"):
                    module = candidate

            if module is None:
                return _handle_fail(
                    "unknown",
                    "No module found — pass module as first arg or 'module' kwarg",
                    on_fail,
                    func_or_class,
                    args,
                    kwargs,
                )

            return _check_and_run(
                module, func_or_class, args, kwargs,
                min_score, require_signature, required_capabilities, on_fail,
            )

        return wrapper

    return decorator


def _check_and_run(
    module: Any,
    func: Callable,
    args: tuple,
    kwargs: dict,
    min_score: int,
    require_signature: bool,
    required_capabilities: Optional[list[str]],
    on_fail: str,
) -> Any:
    """Run KYA verification checks and execute the function if passed."""
    card = get_card(module)
    if card is None:
        module_name = type(module).__name__
        return _handle_fail(
            module_name,
            "No KYA card attached. Use attach_card(module, card) first.",
            on_fail,
            func,
            args,
            kwargs,
        )

    # Run verification
    result = _verify_card_data(card)
    module_name = result.get("agent_name", "unknown")

    if not result["valid"]:
        return _handle_fail(
            module_name,
            f"Card validation failed: {'; '.join(result['errors'])}",
            on_fail,
            func,
            args,
            kwargs,
        )

    # Score check
    if result["completeness_score"] < min_score:
        return _handle_fail(
            module_name,
            f"Score {result['completeness_score']}/100 below required {min_score}",
            on_fail,
            func,
            args,
            kwargs,
        )

    # Signature check
    if require_signature:
        sig_status = result.get("signature", {}).get("status", "unsigned")
        if sig_status != "verified":
            return _handle_fail(
                module_name,
                f"Signature status: {sig_status} (verified required)",
                on_fail,
                func,
                args,
                kwargs,
            )

    # Capabilities check
    if required_capabilities:
        declared = set(result.get("capabilities", []))
        declared_lower = {c.lower() for c in declared}
        missing = [
            c for c in required_capabilities
            if c.lower() not in declared_lower
        ]
        if missing:
            return _handle_fail(
                module_name,
                f"Missing capabilities: {', '.join(missing)}",
                on_fail,
                func,
                args,
                kwargs,
            )

    return func(*args, **kwargs)


def _handle_fail(
    module_name: str,
    reason: str,
    on_fail: str,
    func: Callable,
    args: tuple,
    kwargs: dict,
) -> Any:
    """Handle a verification failure according to the on_fail policy."""
    if on_fail == "raise":
        raise KYAVerificationError(module_name, reason)
    elif on_fail == "skip":
        return None
    elif on_fail == "log":
        import sys

        print(
            f"[dspy-kya] WARNING: {module_name} — {reason}",
            file=sys.stderr,
        )
        return func(*args, **kwargs)
    else:
        raise KYAVerificationError(module_name, reason)
