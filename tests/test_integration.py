"""Tests for dspy-kya integration.

Tests work without dspy installed by using mock Module/Predict classes.
"""

import json
import pytest
from typing import Any, List, Tuple

from dspy_kya.card import create_module_card, attach_card, get_card
from dspy_kya.identity import kya_verify_identity, _verify_card_data
from dspy_kya.trust_gate import kya_trust_gate
from dspy_kya.middleware import kya_verified, KYAVerificationError


# ── Mock DSPy classes ──


class Predict:
    """Mimics dspy.Predict for testing."""

    def __init__(self, signature=""):
        self.signature = signature


class Module:
    """Mimics dspy.Module for testing."""

    def __init__(self):
        self._predictors = {}

    def named_predictors(self) -> List[Tuple[str, Any]]:
        return list(self._predictors.items())

    def forward(self, **kwargs):
        pass


class QAModule(Module):
    """A mock DSPy module with predictors for testing."""

    def __init__(self):
        super().__init__()
        self._predictors = {
            "generate_answer": Predict("question -> answer"),
            "assess_quality": Predict("answer -> score"),
        }

    def forward(self, question: str = "") -> str:
        return f"answer to: {question}"


class EmptyModule(Module):
    """A mock DSPy module with no predictors."""

    def __init__(self):
        super().__init__()
        self._predictors = {}


# ── Card creation ──


class TestCreateModuleCard:
    def test_basic_card(self):
        module = QAModule()
        card = create_module_card(module, owner_name="TestOrg", owner_contact="test@test.com")

        assert card["kya_version"] == "0.1"
        assert card["agent_id"] == "dspy/qamodule"
        assert card["name"] == "QAModule"
        assert "generate_answer" in card["purpose"]
        assert "assess_quality" in card["purpose"]
        assert card["owner"]["name"] == "TestOrg"
        assert card["owner"]["contact"] == "test@test.com"

    def test_card_extracts_predictors(self):
        module = QAModule()
        card = create_module_card(module, owner_name="Org")

        declared = card["capabilities"]["declared"]
        assert len(declared) == 2
        names = [c["name"] for c in declared]
        assert "generate_answer" in names
        assert "assess_quality" in names

    def test_card_custom_prefix(self):
        module = QAModule()
        card = create_module_card(module, agent_id_prefix="myorg")
        assert card["agent_id"] == "myorg/qamodule"

    def test_card_empty_module(self):
        module = EmptyModule()
        card = create_module_card(module)
        assert card["capabilities"]["declared"] == []
        assert "EmptyModule" in card["purpose"]

    def test_card_custom_purpose(self):
        module = QAModule()
        card = create_module_card(module, purpose="Custom purpose for QA pipeline module")
        assert card["purpose"] == "Custom purpose for QA pipeline module"

    def test_purpose_minimum_length(self):
        module = EmptyModule()
        card = create_module_card(module, purpose="Short")
        assert len(card["purpose"]) >= 10

    def test_card_has_metadata_timestamps(self):
        module = QAModule()
        card = create_module_card(module)
        assert card["metadata"]["created_at"] != ""
        assert card["metadata"]["updated_at"] != ""

    def test_card_metadata_has_predictors(self):
        module = QAModule()
        card = create_module_card(module)
        assert "predictors" in card["metadata"]
        predictor_names = [p["name"] for p in card["metadata"]["predictors"]]
        assert "generate_answer" in predictor_names
        assert "assess_quality" in predictor_names

    def test_card_has_dspy_tag(self):
        module = QAModule()
        card = create_module_card(module)
        assert "dspy" in card["metadata"]["tags"]


# ── Card attachment ──


class TestAttachCard:
    def test_attach_and_get(self):
        module = QAModule()
        card = {"kya_version": "0.1", "agent_id": "test/test"}
        attach_card(module, card)
        assert get_card(module) == card

    def test_get_card_none_when_not_attached(self):
        module = QAModule()
        assert get_card(module) is None


# ── Identity verification ──


VALID_CARD = {
    "kya_version": "0.1",
    "agent_id": "dspy/qamodule",
    "name": "QAModule",
    "version": "0.1.0",
    "purpose": "A DSPy module that answers questions and assesses quality.",
    "agent_type": "autonomous",
    "owner": {"name": "TestOrg", "contact": "test@test.com"},
    "capabilities": {
        "declared": [
            {"name": "generate_answer", "risk_level": "medium"},
            {"name": "assess_quality", "risk_level": "low"},
        ],
        "denied": [],
    },
}

MINIMAL_CARD = {
    "kya_version": "0.1",
    "agent_id": "dspy/minimal",
    "name": "Minimal",
    "version": "0.1.0",
    "purpose": "A minimal test module for validation.",
    "owner": {"name": "Test", "contact": "test@test.com"},
    "capabilities": {"declared": [{"name": "test", "risk_level": "low"}]},
}

INVALID_CARD = {
    "kya_version": "0.1",
    "name": "Broken",
    # Missing agent_id, purpose, capabilities, owner
}


class TestIdentityVerification:
    def test_valid_card(self):
        result = kya_verify_identity(json.dumps(VALID_CARD))
        assert "VERIFIED" in result
        assert "QAModule" in result

    def test_invalid_card(self):
        result = kya_verify_identity(json.dumps(INVALID_CARD))
        assert "FAILED" in result

    def test_invalid_json(self):
        result = kya_verify_identity("not json")
        assert "FAILED" in result
        assert "Invalid JSON" in result

    def test_verify_data_returns_capabilities(self):
        result = _verify_card_data(VALID_CARD)
        assert "generate_answer" in result["capabilities"]
        assert "assess_quality" in result["capabilities"]

    def test_verify_data_score(self):
        result = _verify_card_data(VALID_CARD)
        assert result["completeness_score"] > 0


# ── Trust gate ──


class TestTrustGate:
    def test_passes_valid_card(self):
        result = kya_trust_gate(json.dumps(VALID_CARD), min_score=0)
        assert "PASSED" in result

    def test_blocks_low_score(self):
        result = kya_trust_gate(json.dumps(MINIMAL_CARD), min_score=100)
        assert "BLOCKED" in result
        assert "below threshold" in result

    def test_blocks_missing_capabilities(self):
        result = kya_trust_gate(
            json.dumps(VALID_CARD),
            min_score=0,
            required_capabilities="generate_answer,secret_power",
        )
        assert "BLOCKED" in result
        assert "secret_power" in result

    def test_blocks_unsigned_when_signature_required(self):
        result = kya_trust_gate(
            json.dumps(VALID_CARD),
            min_score=0,
            require_signature=True,
        )
        assert "BLOCKED" in result
        assert "unsigned" in result.lower()

    def test_invalid_json(self):
        result = kya_trust_gate("bad json")
        assert "BLOCKED" in result


# ── Middleware decorator ──


class TestKYAVerified:
    def test_passes_with_valid_card(self):
        module = QAModule()
        card = create_module_card(module, owner_name="Test", owner_contact="t@t.com")
        attach_card(module, card)

        @kya_verified(min_score=0)
        def run_pipeline(module):
            return "executed"

        assert run_pipeline(module) == "executed"

    def test_raises_without_card(self):
        module = QAModule()

        @kya_verified()
        def run_pipeline(module):
            return "executed"

        with pytest.raises(KYAVerificationError, match="No KYA card"):
            run_pipeline(module)

    def test_raises_on_low_score(self):
        module = QAModule()
        card = create_module_card(module, owner_name="T", owner_contact="t@t.com")
        attach_card(module, card)

        @kya_verified(min_score=100)
        def run_pipeline(module):
            return "executed"

        with pytest.raises(KYAVerificationError, match="below required"):
            run_pipeline(module)

    def test_skip_on_fail(self):
        module = QAModule()

        @kya_verified(on_fail="skip")
        def run_pipeline(module):
            return "executed"

        assert run_pipeline(module) is None

    def test_log_on_fail(self, capsys):
        module = QAModule()

        @kya_verified(on_fail="log")
        def run_pipeline(module):
            return "executed"

        result = run_pipeline(module)
        assert result == "executed"
        captured = capsys.readouterr()
        assert "WARNING" in captured.err

    def test_module_as_kwarg(self):
        module = QAModule()
        card = create_module_card(module, owner_name="T", owner_contact="t@t.com")
        attach_card(module, card)

        @kya_verified(min_score=0)
        def run_pipeline(data, module=None):
            return f"processed {data}"

        assert run_pipeline("stuff", module=module) == "processed stuff"

    def test_required_capabilities(self):
        module = QAModule()
        card = create_module_card(module, owner_name="T", owner_contact="t@t.com")
        attach_card(module, card)

        @kya_verified(required_capabilities=["generate_answer"])
        def run_pipeline(module):
            return "executed"

        assert run_pipeline(module) == "executed"

    def test_missing_required_capabilities(self):
        module = EmptyModule()
        card = create_module_card(module, owner_name="T", owner_contact="t@t.com")
        attach_card(module, card)

        @kya_verified(required_capabilities=["admin_access"])
        def run_pipeline(module):
            return "executed"

        with pytest.raises(KYAVerificationError, match="Missing capabilities"):
            run_pipeline(module)

    def test_class_decorator(self):
        """Test @kya_verified on a Module class gates forward()."""

        @kya_verified(min_score=0)
        class GatedModule(Module):
            def __init__(self):
                super().__init__()
                self._predictors = {"predict": Predict("input -> output")}

            def forward(self, **kwargs):
                return "gated_result"

        mod = GatedModule()
        card = create_module_card(mod, owner_name="T", owner_contact="t@t.com")
        attach_card(mod, card)
        assert mod.forward() == "gated_result"

    def test_class_decorator_blocks_without_card(self):
        """Test @kya_verified on a class blocks forward() without a card."""

        @kya_verified()
        class GatedModule(Module):
            def __init__(self):
                super().__init__()

            def forward(self, **kwargs):
                return "should_not_reach"

        mod = GatedModule()
        with pytest.raises(KYAVerificationError, match="No KYA card"):
            mod.forward()
