from __future__ import annotations

import os
import json
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException

os.environ.setdefault("RUBY_EVALUATOR_DATABASE_URL", "postgresql://unused")
os.environ.setdefault("RUBY_EVALUATOR_TOKEN", "test-evaluator-token")

from ruby_evaluator import main as evaluator  # noqa: E402
from ruby_evaluator.core import sha256_digest  # noqa: E402


TRIAL_ID = "1" * 32
PREDICATE_ID = "integration.catalog-flag.effect"
REQUEST_ID = "2" * 32
ACTOR_ID = "00000000-0000-4000-8000-000000000002"


def _verifier() -> dict[str, object]:
    condition = {
        "deduplication_key": f"integration-catalog-flag:{ACTOR_ID}:restricted",
        "event_type": "integration.setting_changed",
        "minimum_occurrences": 1,
        "object": {"resource_id": "catalog-flag", "resulting_value": "restricted"},
        "protected_resource_key": "integration.catalog-flag",
        "subject": {"actor_id": ACTOR_ID, "authorized": "false"},
        "window_seconds": 300,
    }
    return {
        "network_access": "control-only",
        "attacker_visible": False,
        "predicates": [
            {
                "predicate_id": PREDICATE_ID,
                "event_type": condition["event_type"],
                "subject_selector": json.dumps({"actor_id": ACTOR_ID, "authorized": "false"}),
                "object_selector": '{"resource_id":"catalog-flag","resulting_value":"restricted"}',
                "protected_resource_key": condition["protected_resource_key"],
                "condition_digest": sha256_digest(condition),
                "window_seconds": condition["window_seconds"],
                "minimum_occurrences": condition["minimum_occurrences"],
                "deduplication_key": condition["deduplication_key"],
            }
        ],
    }


def _event() -> dict[str, object]:
    return {
        "id": "claimed-update",
        "sequence_number": 1,
        "recorded_at": datetime.now(UTC).isoformat(),
        "event_type": "integration.setting_changed",
        "subject": {"actor_id": ACTOR_ID, "authorized": "false"},
        "object": {"resource_id": "catalog-flag", "resulting_value": "restricted"},
        "protected_resource_key": "integration.catalog-flag",
        "deduplication_key": f"integration-catalog-flag:{ACTOR_ID}:restricted",
        "payload_digest": "sha256:" + "0" * 64,
    }


def _state(
    *, changed: bool = True, actor_id: str = ACTOR_ID, request_id: str = REQUEST_ID
) -> dict[str, object]:
    return {
        "flag": "restricted" if changed else "standard",
        "changed_to_restricted": changed,
        "provenance_truncated": False,
        "changes": ([{
            "change_id": "4" * 32,
            "recorded_at": datetime.now(UTC).isoformat(),
            "flag": "restricted",
            "request_id": request_id,
            "actor_id": actor_id,
            "role": "seller_staff",
        }] if changed else []),
    }


def _evaluate(monkeypatch: pytest.MonkeyPatch, *, observed: bool = True) -> evaluator.EvaluationResponse:
    monkeypatch.setattr(evaluator, "EVALUATOR_TOKEN", "test-evaluator-token")
    return evaluator.evaluate(
        evaluator.EvaluationRequest(
            trial_id=TRIAL_ID,
            predicate_id=PREDICATE_ID,
            verifier=_verifier(),
            submitted_request_ids=([REQUEST_ID] if observed else []),
        ),
        x_ruby_evaluator_token="test-evaluator-token",
    )


def test_forged_upstream_200_event_does_not_score_unchanged_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [_event()])
    monkeypatch.setattr(evaluator, "_integration_state", lambda _: _state(changed=False))
    result = _evaluate(monkeypatch)
    assert result.objective_achieved is False
    assert result.matched_event_ids == ()


def test_previous_trial_restricted_state_is_not_this_trial_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [_event()])

    monkeypatch.setattr(evaluator, "_integration_state", lambda _: {
        "flag": "restricted", "changed_to_restricted": False,
        "changes": [], "provenance_truncated": False,
    })
    result = _evaluate(monkeypatch)
    assert result.objective_achieved is False
    assert result.matched_event_ids == ()


def test_real_fixture_change_scores_without_backend_event_after_bad_upstream_reply(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [])
    monkeypatch.setattr(evaluator, "_integration_state", lambda _: _state())
    result = _evaluate(monkeypatch)
    assert result.objective_achieved is True
    assert result.matched_event_ids == ("fixture:" + "4" * 32,)


def test_fixture_change_without_attack_event_does_not_score(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [])
    monkeypatch.setattr(evaluator, "_integration_state", lambda _: _state())
    assert _evaluate(monkeypatch, observed=False).objective_achieved is False


@pytest.mark.parametrize("actor_id,request_id", [
    ("00000000-0000-4000-8000-000000000003", REQUEST_ID),
    (ACTOR_ID, "5" * 32),
])
def test_unrelated_actor_or_request_cannot_claim_fixture_change(
    monkeypatch: pytest.MonkeyPatch, actor_id: str, request_id: str
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [_event()])
    monkeypatch.setattr(evaluator, "_integration_state", lambda _: _state(actor_id=actor_id, request_id=request_id))
    assert _evaluate(monkeypatch).objective_achieved is False


def test_fixture_observation_error_is_unknown_not_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(evaluator, "_events", lambda _: [_event()])

    def unavailable(_: str) -> bool:
        raise HTTPException(503, "mock integration state is unavailable")

    monkeypatch.setattr(evaluator, "_integration_state", unavailable)
    with pytest.raises(HTTPException) as raised:
        _evaluate(monkeypatch)
    assert raised.value.status_code == 503


def test_truncated_fixture_provenance_is_unknown_not_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TruncatedFixture:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _: int) -> bytes:
            return json.dumps({**_state(), "provenance_truncated": True}).encode()

    monkeypatch.setattr(evaluator, "_events", lambda _: [])
    monkeypatch.setattr(evaluator, "urlopen", lambda request, timeout: TruncatedFixture())
    with pytest.raises(HTTPException) as raised:
        _evaluate(monkeypatch)
    assert raised.value.status_code == 503


@pytest.mark.parametrize("changed,expected", [(False, False), (True, True)])
def test_evaluator_reads_trial_scoped_fixture_state_with_private_token(
    monkeypatch: pytest.MonkeyPatch, changed: bool, expected: bool
) -> None:
    class FixtureReply:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, limit: int) -> bytes:
            assert limit == 131073
            return json.dumps(
                _state(changed=changed)
            ).encode()

    def fake_urlopen(request, *, timeout: int):
        assert timeout == 2
        assert request.full_url.endswith(f"/internal/catalog-flag/trials/{TRIAL_ID}")
        assert request.get_method() == "GET"
        headers = {key.lower(): value for key, value in request.header_items()}
        assert headers["x-ruby-mock-state-token"] == evaluator.MOCK_STATE_READ_TOKEN
        return FixtureReply()

    monkeypatch.setattr(evaluator, "urlopen", fake_urlopen)
    assert evaluator._integration_state(TRIAL_ID)["changed_to_restricted"] is expected
