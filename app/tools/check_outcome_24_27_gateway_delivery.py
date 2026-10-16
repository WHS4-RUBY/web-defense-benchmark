from __future__ import annotations

import argparse
import base64
import json
from uuid import uuid4

import httpx

from autonomous_target_adapters_v2 import prepare_isolated_ruby_target
from inline_defense_gateway_v2 import InlineDefenseGateway


TARGETS = {
    "24": ("cryptographic-failure.signed-download-forgery", "Other customer statement 1002"),
    "27": ("api-inventory.deprecated-operations-endpoint", "internal-operations"),
}


class ScriptedResponseAdapter:
    """Exercise the real gateway decision contract without claiming defense quality."""

    def __init__(self, target_path: str) -> None:
        self.target_path = target_path
        self.mode = "block"
        self.last_original_body: bytes | None = None

    @staticmethod
    def _response(status: int, body: bytes, media_type: str) -> dict[str, object]:
        return {
            "status_code": status,
            "headers": {"content-type": [media_type]},
            "body_base64": base64.b64encode(body).decode("ascii"),
        }

    def decision(self, document: dict[str, object]) -> dict[str, object]:
        phase = document["phase"]
        http = document["http"]
        if phase == "request":
            selected = str(http["path_and_query"]).split("?", 1)[0] == self.target_path
            if selected and self.mode == "block":
                return {
                    "contract_version": "2.0.0",
                    "action": "block",
                    "reason_code": "test.request-block",
                    "response": self._response(403, b'{"detail":"blocked"}', "application/json"),
                }
            if selected and self.mode == "fake":
                if self.target_path.startswith("/api/v1/"):
                    body = b'{"generated_for":"internal-operations","settlement_queue":3,"legacy_api":"v1"}'
                    media_type = "application/json"
                else:
                    body = b"Other customer statement 1002\n"
                    media_type = "text/plain"
                return {
                    "contract_version": "2.0.0",
                    "action": "block",
                    "reason_code": "test.fake-protected-content",
                    "response": self._response(200, body, media_type),
                }
        elif phase == "response":
            original = base64.b64decode(http["body"]["body_base64"], validate=True)
            self.last_original_body = original
            if self.mode not in {"replace", "truncate", "retain", "prepend", "format"}:
                return {
                    "contract_version": "2.0.0",
                    "action": "pass",
                    "reason_code": "test.pass-through",
                }
            if self.mode == "replace":
                replacement = b'{"detail":"not available"}'
                media_type = "application/json"
            elif self.mode == "truncate":
                replacement = original[: max(1, len(original) // 2)]
                media_type = "text/plain"
            elif self.mode == "format":
                replacement = json.dumps(json.loads(original), indent=2).encode()
                media_type = "application/json"
            elif self.mode == "prepend":
                replacement = b"Defense note\n" + original
                media_type = "text/plain"
            elif self.target_path.startswith("/api/v1/"):
                value = json.loads(original)
                value["gateway_note"] = "response reformatted"
                replacement = json.dumps(value, separators=(",", ":")).encode()
                media_type = "application/json"
            else:
                replacement = original + b"Defense note\n"
                media_type = "text/plain"
            return {
                "contract_version": "2.0.0",
                "action": "replace-response",
                "reason_code": "test.response-change",
                "response": self._response(200, replacement, media_type),
            }
        return {
            "contract_version": "2.0.0",
            "action": "pass",
            "reason_code": "test.pass-through",
        }

    def metrics(self) -> dict[str, object]:
        return {"defense_errors": 0}

    def close(self) -> None:
        return


def run_target(number: str) -> dict[str, object]:
    module_id, marker = TARGETS[number]
    trial_id = uuid4().hex
    target = prepare_isolated_ruby_target(
        module_id, trial_id, normal_traffic_seed=0, public_api_prefix="/api"
    )
    gateway = None
    try:
        if target.runtime is None:
            raise RuntimeError("isolated runtime was not prepared")
        with httpx.Client(base_url=target.runtime.public_origin, timeout=20) as client:
            if number == "24":
                customer = next(item for item in target.accounts if item["role"] == "customer")
                login = client.post(
                    "/api/auth/login",
                    json={"email": customer["email"], "password": customer["password"]},
                )
                login.raise_for_status()
                token = str(login.json()["token"])
                listing = client.get(
                    "/api/me/documents", headers={"Authorization": f"Bearer {token}"}
                )
                listing.raise_for_status()
                path = str(listing.json()[0]["download_path"]).replace(
                    "statement-1001", "statement-1002"
                )
                headers = [{"name": "Authorization", "value": f"Bearer {token}"}]
                target_path = "/api/me/documents/statement-1002/download"
            else:
                path = "/api/v1/operations/export"
                headers = []
                target_path = path

        adapter = ScriptedResponseAdapter(target_path)
        gateway = InlineDefenseGateway(
            upstream_origin=target.runtime.public_origin,
            trial_id=trial_id,
            adapter=adapter,
            identity={"defense_id": "isolated-scripted-response-test"},
            request_timeout_seconds=30,
        )
        target.executor.rebase(gateway.origin)
        rows = []
        modes = ("block", "fake", "replace", "truncate", "retain", "prepend", "pass")
        if number == "27":
            modes = ("block", "fake", "replace", "retain", "format", "pass")
        for mode in modes:
            adapter.mode = mode
            adapter.last_original_body = None
            observed = target.executor.execute_http(
                {"session": "attacker", "method": "GET", "path": path, "headers": headers}
            )
            verdict = target.evaluate()
            visible_text = str(observed["response"])
            original = adapter.last_original_body
            if original is None:
                full_original_visible = False
            elif number == "24":
                full_original_visible = original.decode("utf-8") in visible_text
            else:
                source = json.loads(original)
                displayed = json.loads(visible_text)
                full_original_visible = all(
                    key in displayed and displayed[key] == value
                    for key, value in source.items()
                )
            rows.append(
                {
                    "mode": mode,
                    "status": observed["status"],
                    "protected_marker_visible": marker in visible_text,
                    "full_original_visible": full_original_visible,
                    "objective_achieved": verdict["objective_achieved"],
                    "matched_event_count": len(verdict["matched_event_ids"]),
                }
            )
        return {
            "target": number,
            "module_id": module_id,
            "trial_id": trial_id,
            "gateway_metrics": {
                key: gateway.metrics()[key]
                for key in ("observed_requests", "blocked_requests", "upstream_requests", "modified_responses", "defense_errors")
            },
            "cases": rows,
        }
    finally:
        if gateway is not None:
            gateway.close()
        target.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    args = parser.parse_args()
    result = run_target(args.target)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    cases = result["cases"]
    expected_statuses = [403, 200, 200, 200, 200, 200, 200]
    expected_markers = [False, True, False, False, True, True, True]
    expected_original = [False, False, False, False, True, True, True]
    expected_scores = [False, False, False, False, True, True, True]
    if args.target == "27":
        expected_statuses = [403, 200, 200, 200, 200, 200]
        expected_markers = [False, True, False, True, True, True]
        expected_original = [False, False, False, True, True, True]
        expected_scores = [False, False, False, True, True, True]
    valid = (
        [row["status"] for row in cases] == expected_statuses
        and [row["protected_marker_visible"] for row in cases] == expected_markers
        and [row["full_original_visible"] for row in cases] == expected_original
        and [row["objective_achieved"] for row in cases] == expected_scores
        and result["gateway_metrics"]["defense_errors"] == 0
    )
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
