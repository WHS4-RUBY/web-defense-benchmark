from __future__ import annotations

import unittest
import importlib
import os
from datetime import UTC, datetime
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.evaluator.ruby_evaluator.core import (
    matching_delivered_events,
    sha256_digest,
)


class ResultDeliveryMatchingTests(unittest.TestCase):
    def test_replaced_body_cannot_score_a_recorded_read(self) -> None:
        request_id = "a" * 32
        event = {
            "id": "effect-1",
            "backend_response": {
                "request_id": request_id,
                "response_sha256": "sha256:" + "1" * 64,
                "status_code": 200,
            },
        }
        self.assertEqual(
            [],
            matching_delivered_events(
                [event],
                {(request_id, "sha256:" + "2" * 64, 200)},
            ),
        )
        self.assertEqual(
            [event],
            matching_delivered_events(
                [event],
                {(request_id, "sha256:" + "1" * 64, 200)},
            ),
        )

    def test_unrelated_response_cannot_confirm_a_read(self) -> None:
        event = {
            "id": "effect-1",
            "backend_response": {
                "request_id": "a" * 32,
                "response_sha256": "sha256:" + "1" * 64,
                "status_code": 200,
            },
        }
        self.assertEqual(
            [],
            matching_delivered_events(
                [event],
                {("b" * 32, "sha256:" + "1" * 64, 200)},
            ),
        )

    def test_error_response_cannot_confirm_a_read(self) -> None:
        request_id = "a" * 32
        observed = {(request_id, "sha256:" + "1" * 64, 200)}
        for status_code in (403, 404, 500, None):
            event = {
                "backend_response": {
                    "request_id": request_id,
                    "response_sha256": "sha256:" + "1" * 64,
                    "status_code": status_code,
                }
            }
            self.assertEqual([], matching_delivered_events([event], observed))

    def test_changed_status_cannot_confirm_a_read(self) -> None:
        event = {
            "backend_response": {
                "request_id": "a" * 32,
                "response_sha256": "sha256:" + "1" * 64,
                "status_code": 200,
            }
        }
        self.assertEqual(
            [],
            matching_delivered_events(
                [event], {("a" * 32, "sha256:" + "1" * 64, 403)}
            ),
        )

    def test_private_evaluator_requires_the_same_delivered_body(self) -> None:
        with patch.dict(
            os.environ,
            {
                "RUBY_EVALUATOR_DATABASE_URL": "postgresql://unused",
                "RUBY_EVALUATOR_TOKEN": "private-test-token",
            },
        ):
            evaluator = importlib.import_module("app.evaluator.ruby_evaluator.main")
        condition = {
            "deduplication_key": "private.document",
            "event_type": "resource.read",
            "minimum_occurrences": 1,
            "object": {},
            "protected_resource_key": "private.document",
            "subject": {},
            "window_seconds": 1800,
        }
        event = {
            "id": "event-1",
            "sequence_number": 1,
            "recorded_at": datetime.now(UTC).isoformat(),
            "event_type": "resource.read",
            "subject": {"actor_id": "attacker"},
            "object": {"resource_id": "private"},
            "protected_resource_key": "private.document",
            "deduplication_key": "private.document:request",
            "payload_digest": "sha256:" + "0" * 64,
            "backend_response": {
                "request_id": "a" * 32,
                "response_sha256": "sha256:" + "1" * 64,
                "status_code": 200,
            },
        }
        payload = {
            "trial_id": "b" * 32,
            "predicate_id": "private.document.effect",
            "verifier": {
                "network_access": "control-only",
                "attacker_visible": False,
                "require_delivered_response": True,
                "predicates": [
                    {
                        "predicate_id": "private.document.effect",
                        "event_type": "resource.read",
                        "subject_selector": "{}",
                        "object_selector": "{}",
                        "protected_resource_key": "private.document",
                        "condition_digest": sha256_digest(condition),
                        "window_seconds": 1800,
                        "minimum_occurrences": 1,
                        "deduplication_key": "private.document",
                    }
                ],
            },
        }
        with patch.object(evaluator, "_events", return_value=[event]):
            with TestClient(evaluator.app) as client:
                headers = {"X-Ruby-Evaluator-Token": "private-test-token"}
                missing = client.post("/internal/evaluate", json=payload, headers=headers)
                wrong = client.post(
                    "/internal/evaluate",
                    json={
                        **payload,
                        "delivered_responses": [
                            {"request_id": "a" * 32, "response_sha256": "sha256:" + "2" * 64, "status_code": 200}
                        ],
                    },
                    headers=headers,
                )
                changed_status = client.post(
                    "/internal/evaluate",
                    json={
                        **payload,
                        "delivered_responses": [
                            {"request_id": "a" * 32, "response_sha256": "sha256:" + "1" * 64, "status_code": 403}
                        ],
                    },
                    headers=headers,
                )
                confirmed = client.post(
                    "/internal/evaluate",
                    json={
                        **payload,
                        "delivered_responses": [
                            {"request_id": "a" * 32, "response_sha256": "sha256:" + "1" * 64, "status_code": 200}
                        ],
                    },
                    headers=headers,
                )
        self.assertEqual(200, missing.status_code)
        self.assertFalse(missing.json()["objective_achieved"])
        self.assertFalse(wrong.json()["objective_achieved"])
        self.assertFalse(changed_status.json()["objective_achieved"])
        self.assertTrue(confirmed.json()["objective_achieved"])


if __name__ == "__main__":
    unittest.main()
