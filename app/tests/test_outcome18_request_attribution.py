from __future__ import annotations

import httpx
import pytest

from autonomous_experiment_v2 import ActionExecutor


def test_private_request_id_is_recorded_even_when_no_response_arrives() -> None:
    submitted: list[str] = []
    reached_transport: list[str] = []

    def disconnect(request: httpx.Request) -> httpx.Response:
        reached_transport.append(request.headers["X-Ruby-Trial-Request-Id"])
        raise httpx.ConnectError("response lost", request=request)

    executor = ActionExecutor(
        "http://127.0.0.1:18231",
        private_request_observer=submitted.append,
    )
    executor.sessions["attacker"] = httpx.Client(
        base_url="http://127.0.0.1:18231",
        transport=httpx.MockTransport(disconnect),
    )
    try:
        with pytest.raises(httpx.ConnectError):
            executor.execute_http({
                "kind": "http",
                "session": "attacker",
                "method": "GET",
                "path": "/api/products",
            })
    finally:
        executor.close()

    assert len(submitted) == 1
    assert reached_transport == submitted


def test_model_cannot_override_private_request_id() -> None:
    submitted: list[str] = []
    reached_transport: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        reached_transport.append(request.headers["X-Ruby-Trial-Request-Id"])
        return httpx.Response(200, json={"items": []})

    executor = ActionExecutor(
        "http://127.0.0.1:18231",
        private_request_observer=submitted.append,
    )
    executor.sessions["attacker"] = httpx.Client(
        base_url="http://127.0.0.1:18231",
        transport=httpx.MockTransport(respond),
    )
    try:
        result = executor.execute_http({
            "kind": "http",
            "session": "attacker",
            "method": "GET",
            "path": "/api/products",
            "headers": [{"name": "X-Ruby-Trial-Request-Id", "value": "f" * 32}],
        })
    finally:
        executor.close()

    assert result["status"] == 200
    assert len(submitted) == 1
    assert reached_transport == submitted
    assert submitted[0] != "f" * 32
    assert "_trial_request_id" not in result
