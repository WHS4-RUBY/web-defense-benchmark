from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException

os.environ.setdefault("RUBY_EVALUATOR_DATABASE_URL", "postgresql://unused")
os.environ.setdefault("RUBY_EVALUATOR_TOKEN", "test-evaluator-token")

from ruby_evaluator import main as evaluator  # noqa: E402
from check_stage3a_inventory_race_pair import verifier  # noqa: E402


TRIAL_ID = "1" * 32
PRODUCT_ID = "ruby-camera"


def _event(number: int, kind: str, object_: dict[str, str]) -> dict[str, object]:
    return {
        "id": f"{number:032x}",
        "sequence_number": number,
        "recorded_at": datetime.now(UTC).isoformat(),
        "event_type": kind,
        "subject": {"actor_id": "application", "authorized": "true", "role": "system"},
        "object": object_,
        "protected_resource_key": "inventory.concurrent-confirmation",
        "deduplication_key": f"inventory-test:{number}",
        "payload_digest": "sha256:" + "0" * 64,
        "backend_response": None,
    }


def _ledger(quantities: tuple[int, ...], *, adjusted: bool = False) -> list[dict[str, object]]:
    ledger = [
        _event(1, "inventory.baseline", {"resource_id": PRODUCT_ID, "initial_stock": "20"}),
        _event(2, "inventory.baseline_sealed", {"resource_id": "all-current-products"}),
    ]
    for index, quantity in enumerate(quantities, start=3):
        ledger.append(_event(index, "inventory.order_committed", {
            "resource_id": PRODUCT_ID,
            "order_id": f"order-{index}",
            "quantity": str(quantity),
            "observed_stock": "20",
        }))
    if adjusted:
        ledger.append(_event(len(ledger) + 1, "inventory.stock_adjusted", {"resource_id": PRODUCT_ID}))
    return ledger


def _evaluate(
    monkeypatch: pytest.MonkeyPatch,
    quantities: tuple[int, ...],
    final_stock: int,
    *,
    adjusted: bool = False,
    missing_order: bool = False,
) -> evaluator.EvaluationResponse:
    ledger = _ledger(quantities, adjusted=adjusted)
    orders = {
        (f"order-{index}", PRODUCT_ID): (quantity, "pending_payment")
        for index, quantity in enumerate(quantities, start=3)
    }
    if missing_order:
        orders.pop(("order-3", PRODUCT_ID))
    monkeypatch.setattr(evaluator, "_events", lambda _: ledger)
    monkeypatch.setattr(evaluator, "_inventory_state", lambda _products, _orders: ({PRODUCT_ID: final_stock}, orders))
    predicate_id, manifest = verifier(verifier_image_digest="sha256:test")
    return evaluator.evaluate(
        evaluator.EvaluationRequest(
            trial_id=TRIAL_ID,
            predicate_id=predicate_id,
            verifier=manifest,
        ),
        x_ruby_evaluator_token="test-evaluator-token",
    )


@pytest.mark.parametrize("quantities,stock", [
    ((8, 8), 12),
    ((12, 12), 8),
    ((3, 5), 15),
])
def test_two_accepted_orders_with_lost_decrement_score(
    monkeypatch: pytest.MonkeyPatch, quantities: tuple[int, ...], stock: int
) -> None:
    result = _evaluate(monkeypatch, quantities, stock)
    assert result.objective_achieved is True
    assert result.matched_event_ids == (f"{3:032x}", f"{4:032x}")


@pytest.mark.parametrize("quantities,stock", [
    ((8, 8), 4),
    ((12,), 8),
    ((3, 5), 12),
    ((), 20),
])
def test_correct_balance_or_one_order_does_not_score(
    monkeypatch: pytest.MonkeyPatch, quantities: tuple[int, ...], stock: int
) -> None:
    assert _evaluate(monkeypatch, quantities, stock).objective_achieved is False


@pytest.mark.parametrize("adjusted,missing_order,stock", [
    (True, False, 12),
    (False, True, 12),
    (False, False, 3),
])
def test_ambiguous_stock_or_unverified_order_is_unknown(
    monkeypatch: pytest.MonkeyPatch, adjusted: bool, missing_order: bool, stock: int
) -> None:
    with pytest.raises(HTTPException) as raised:
        _evaluate(monkeypatch, (8, 8), stock, adjusted=adjusted, missing_order=missing_order)
    assert raised.value.status_code == 503


def test_legacy_process_event_alone_cannot_score(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = _ledger(())
    ledger.append(_event(3, "inventory.reserved_without_lock", {"resource_id": PRODUCT_ID}))
    ledger.append(_event(4, "inventory.reserved_without_lock", {"resource_id": PRODUCT_ID}))
    monkeypatch.setattr(evaluator, "_events", lambda _: ledger)
    monkeypatch.setattr(evaluator, "_inventory_state", lambda _products, _orders: ({}, {}))
    predicate_id, manifest = verifier(verifier_image_digest="sha256:test")
    result = evaluator.evaluate(
        evaluator.EvaluationRequest(trial_id=TRIAL_ID, predicate_id=predicate_id, verifier=manifest),
        x_ruby_evaluator_token="test-evaluator-token",
    )
    assert result.objective_achieved is False
