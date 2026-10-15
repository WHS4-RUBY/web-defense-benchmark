from __future__ import annotations

from fastapi.testclient import TestClient

from ruby_mock import main as fixture


def _state_without_provenance(client: TestClient, path: str, headers: dict[str, str]) -> dict[str, object]:
    state = client.get(path, headers=headers).json()
    assert isinstance(state.pop("changes"), list)
    assert state.pop("provenance_truncated") is False
    return state


def test_only_actual_trial_change_creates_private_outcome() -> None:
    first_trial = "1" * 32
    second_trial = "2" * 32
    with TestClient(fixture.app) as client:
        client.post("/internal/reset")
        private_path = f"/internal/catalog-flag/trials/{first_trial}"
        assert client.get(private_path).status_code == 403
        read_headers = {"X-Ruby-Mock-State-Token": fixture.MOCK_STATE_READ_TOKEN}
        assert _state_without_provenance(client, private_path, read_headers) == {
            "flag": "standard",
            "changed_to_restricted": False,
        }

        changed = client.post(
            "/internal/catalog-flag",
            headers={
                "X-Integration-Credential": fixture.SERVICE_CREDENTIAL,
                "X-Ruby-Trial-Id": first_trial,
            },
            json={"flag": "restricted"},
        )
        assert changed.status_code == 200
        assert _state_without_provenance(client, private_path, read_headers) == {
            "flag": "restricted",
            "changed_to_restricted": True,
        }
        # A prior trial's restricted value is not a fresh change for another trial.
        same_value = client.post(
            "/internal/catalog-flag",
            headers={
                "X-Integration-Credential": fixture.SERVICE_CREDENTIAL,
                "X-Ruby-Trial-Id": second_trial,
            },
            json={"flag": "restricted"},
        )
        assert same_value.status_code == 200
        assert _state_without_provenance(
            client, f"/internal/catalog-flag/trials/{second_trial}", read_headers
        ) == {"flag": "restricted", "changed_to_restricted": False}

        client.post("/internal/reset")
        assert _state_without_provenance(client, private_path, read_headers) == {
            "flag": "standard",
            "changed_to_restricted": False,
        }


def test_changed_fixture_records_authenticated_request_provenance() -> None:
    trial_id = "3" * 32
    request_id = "4" * 32
    actor_id = "00000000-0000-4000-8000-000000000002"
    headers = {
        "X-Integration-Credential": fixture.SERVICE_CREDENTIAL,
        "X-Ruby-Trial-Id": trial_id,
        "X-Ruby-Trial-Request-Id": request_id,
        "X-Ruby-Actor-Id": actor_id,
        "X-Ruby-Actor-Role": "seller_staff",
    }
    read_headers = {"X-Ruby-Mock-State-Token": fixture.MOCK_STATE_READ_TOKEN}
    with TestClient(fixture.app) as client:
        client.post("/internal/reset")
        changed = client.post("/internal/catalog-flag", headers=headers, json={"flag": "restricted"})
        assert changed.status_code == 200
        state = client.get(f"/internal/catalog-flag/trials/{trial_id}", headers=read_headers).json()
        assert state["flag"] == "restricted"
        assert state["changed_to_restricted"] is True
        assert len(state["changes"]) == 1
        provenance = state["changes"][0]
        assert provenance["request_id"] == request_id
        assert provenance["actor_id"] == actor_id
        assert provenance["role"] == "seller_staff"
        assert provenance["flag"] == "restricted"
        assert client.post("/internal/catalog-flag", headers=headers, json={"flag": "restricted"}).status_code == 200
        assert len(client.get(f"/internal/catalog-flag/trials/{trial_id}", headers=read_headers).json()["changes"]) == 1
        client.post("/internal/reset")
