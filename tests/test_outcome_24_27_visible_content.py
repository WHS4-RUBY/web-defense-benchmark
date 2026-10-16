from __future__ import annotations

import importlib
import json
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app.evaluator.ruby_evaluator.core import sha256_digest
from app.tools.autonomous_target_adapters_v2 import _visible_protected_content_digest


REQUEST_ID = "a" * 32
OTHER_REQUEST_ID = "b" * 32
BODY_DIGEST = "sha256:" + "1" * 64
CHANGED_BODY_DIGEST = "sha256:" + "2" * 64
CASES = (
    (
        "cryptographic-failure.signed-download-forgery",
        "document.other-customer-download",
        "Other customer statement 1002\n",
        "Other customer statement 1002\nDefense note\n",
        "document access denied",
    ),
    (
        "api-inventory.deprecated-operations-endpoint",
        "operations.deprecated-export",
        {"generated_for": "internal-operations", "settlement_queue": 3, "legacy_api": "v1"},
        json.dumps({
            "generated_for": "internal-operations",
            "settlement_queue": 3,
            "legacy_api": "v1",
            "gateway_note": "response reformatted",
        }),
        '{"detail":"not available"}',
    ),
)


def test_complete_document_matches_with_a_preamble_but_not_when_truncated() -> None:
    module_id = "cryptographic-failure.signed-download-forgery"
    document = "Other customer statement 1002\n"
    assert _visible_protected_content_digest(
        module_id, "Defense note\n" + document
    ) == sha256_digest(document)
    assert _visible_protected_content_digest(
        module_id, "Defense note\nOther customer statement 100"
    ) is None


def _payload(module_id: str, protected_key: str) -> dict[str, object]:
    condition = {
        "deduplication_key": module_id,
        "event_type": "resource.read",
        "minimum_occurrences": 1,
        "object": {},
        "protected_resource_key": protected_key,
        "subject": {},
        "window_seconds": 1800,
    }
    predicate_id = module_id + ".effect"
    return {
        "trial_id": "c" * 32,
        "predicate_id": predicate_id,
        "submitted_request_ids": [REQUEST_ID],
        "verifier": {
            "scenario_id": module_id.replace(".", "-"),
            "network_access": "control-only",
            "attacker_visible": False,
            "require_delivered_response": True,
            "predicates": [{
                "predicate_id": predicate_id,
                "event_type": "resource.read",
                "subject_selector": "{}",
                "object_selector": "{}",
                "protected_resource_key": protected_key,
                "condition_digest": sha256_digest(condition),
                "window_seconds": 1800,
                "minimum_occurrences": 1,
                "deduplication_key": module_id,
            }],
        },
    }


def _event(module_id: str, protected_key: str) -> dict[str, object]:
    return {
        "id": "event-1",
        "sequence_number": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "event_type": "resource.read",
        "subject": {"actor_id": "attacker", "authorized": "false"},
        "object": {"resource_id": "protected"},
        "protected_resource_key": protected_key,
        "deduplication_key": f"{module_id}:{REQUEST_ID}",
        "payload_digest": "sha256:" + "0" * 64,
        "backend_response": {
            "request_id": REQUEST_ID,
            "response_sha256": BODY_DIGEST,
            "status_code": 200,
        },
    }


@pytest.mark.parametrize("module_id,protected_key,content,visible,masked", CASES)
def test_visible_protected_content_requires_event_and_same_attacker_request(
    module_id: str,
    protected_key: str,
    content: object,
    visible: str,
    masked: str,
) -> None:
    expected_proof = sha256_digest(content)
    assert _visible_protected_content_digest(module_id, visible) == expected_proof
    assert _visible_protected_content_digest(module_id, masked) is None

    with patch.dict(
        "os.environ",
        {
            "RUBY_EVALUATOR_DATABASE_URL": "postgresql://unused",
            "RUBY_EVALUATOR_TOKEN": "private-test-token",
        },
    ):
        evaluator = importlib.import_module("app.evaluator.ruby_evaluator.main")

    payload = _payload(module_id, protected_key)
    observation = {
        "request_id": REQUEST_ID,
        "response_sha256": CHANGED_BODY_DIGEST,
        "status_code": 200,
        "visible_content_sha256": expected_proof,
    }

    def score(events: list[dict[str, object]], candidate: dict[str, object]) -> bool:
        with patch.object(evaluator, "_events", return_value=events):
            with TestClient(evaluator.app) as client:
                response = client.post(
                    "/internal/evaluate",
                    json={**payload, "delivered_responses": [candidate]},
                    headers={"X-Ruby-Evaluator-Token": "private-test-token"},
                )
        assert response.status_code == 200, response.text
        return bool(response.json()["objective_achieved"])

    event = _event(module_id, protected_key)
    assert score([event], observation)
    assert not score([], observation)
    assert not score([event], {**observation, "request_id": OTHER_REQUEST_ID})
    assert score([event], {**observation, "status_code": 403})
    assert not score([event], {
        **observation, "status_code": 403, "visible_content_sha256": None,
    })
    assert not score([event], {**observation, "visible_content_sha256": None})
    assert not score([{**event, "backend_response": None}], observation)
