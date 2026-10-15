from __future__ import annotations

import json
import os
from datetime import UTC, datetime

import pytest

os.environ.setdefault("RUBY_EVALUATOR_DATABASE_URL", "postgresql://unused")
os.environ.setdefault("RUBY_EVALUATOR_TOKEN", "test-evaluator-token")

from ruby_evaluator import main as evaluator  # noqa: E402
from ruby_evaluator.core import sha256_digest  # noqa: E402


TRIAL_ID = "1" * 32
ATTACK_REQUEST_ID = "2" * 32
OTHER_REQUEST_ID = "3" * 32
RESPONSE_DIGEST = "sha256:" + "4" * 64


def _verifier() -> dict[str, object]:
    condition = {
        "deduplication_key": "search-reset-takeover:admin",
        "event_type": "account.taken_over",
        "minimum_occurrences": 1,
        "object": {"target_role": "admin"},
        "protected_resource_key": "admin.account",
        "subject": {"authorized": "false"},
        "window_seconds": 300,
    }
    return {
        "network_access": "control-only",
        "attacker_visible": False,
        "require_delivered_response": True,
        "predicates": [{
            "predicate_id": "admin-session.effect",
            "event_type": condition["event_type"],
            "subject_selector": json.dumps(condition["subject"]),
            "object_selector": json.dumps(condition["object"]),
            "protected_resource_key": condition["protected_resource_key"],
            "condition_digest": sha256_digest(condition),
            "window_seconds": 300,
            "minimum_occurrences": 1,
            "deduplication_key": condition["deduplication_key"],
        }],
    }


def _event(request_id: str) -> dict[str, object]:
    return {
        "id": "admin-session-event",
        "sequence_number": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "event_type": "account.taken_over",
        "subject": {"actor_id": "anonymous", "authorized": "false"},
        "object": {"resource_id": "admin", "target_role": "admin"},
        "protected_resource_key": "admin.account",
        "deduplication_key": "search-reset-takeover:admin:" + request_id,
        "payload_digest": "sha256:" + "0" * 64,
        "backend_response": {
            "request_id": request_id,
            "response_sha256": RESPONSE_DIGEST,
            "status_code": 200,
        },
    }


@pytest.mark.parametrize(
    "originating_request_id,submitted,delivered,expected",
    [
        (ATTACK_REQUEST_ID, True, True, True),
        (OTHER_REQUEST_ID, True, True, False),
        (ATTACK_REQUEST_ID, False, True, False),
        (ATTACK_REQUEST_ID, True, False, False),
    ],
)
def test_admin_session_requires_attacker_request_and_delivery(
    monkeypatch: pytest.MonkeyPatch,
    originating_request_id: str,
    submitted: bool,
    delivered: bool,
    expected: bool,
) -> None:
    monkeypatch.setattr(evaluator, "EVALUATOR_TOKEN", "test-evaluator-token")
    monkeypatch.setattr(evaluator, "_events", lambda _: [_event(originating_request_id)])
    result = evaluator.evaluate(
        evaluator.EvaluationRequest(
            trial_id=TRIAL_ID,
            predicate_id="admin-session.effect",
            verifier=_verifier(),
            submitted_request_ids=[ATTACK_REQUEST_ID] if submitted else [],
            delivered_responses=([{
                "request_id": originating_request_id,
                "response_sha256": RESPONSE_DIGEST,
                "status_code": 200,
            }] if delivered else []),
        ),
        x_ruby_evaluator_token="test-evaluator-token",
    )
    assert result.objective_achieved is expected
