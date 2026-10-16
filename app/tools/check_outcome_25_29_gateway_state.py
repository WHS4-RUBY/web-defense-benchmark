from __future__ import annotations

import argparse
import json
import time
from uuid import uuid4

import httpx

from autonomous_target_adapters_v2 import prepare_isolated_ruby_target
from check_outcome_24_27_gateway_delivery import ScriptedResponseAdapter
from inline_defense_gateway_v2 import InlineDefenseGateway


TARGETS = {
    "25": "resource-consumption.report-export-fanout",
    "26": "business-workflow.bulk-promotion-redemption",
    "28": "security-logging.audit-trail-erasure",
    "29": "software-data-integrity.unsigned-partner-webhook",
}


class StateTestAdapter(ScriptedResponseAdapter):
    def __init__(self, target_path: str) -> None:
        super().__init__(target_path)
        self.last_upstream_status: int | None = None

    def decision(self, document: dict[str, object]) -> dict[str, object]:
        if document["phase"] == "response":
            self.last_upstream_status = int(document["http"]["status_code"])
        return super().decision(document)


def _login(client: httpx.Client, account: dict[str, str]) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": account["email"], "password": account["password"]},
    )
    response.raise_for_status()
    return str(response.json()["token"])


def _paid_order(client: httpx.Client, token: str) -> str:
    headers = {"Authorization": f"Bearer {token}"}
    created = client.post(
        "/api/orders",
        headers=headers,
        json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
    )
    created.raise_for_status()
    order_id = str(created.json()["id"])
    paid = client.post(
        f"/api/orders/{order_id}/pay",
        headers=headers,
        json={"method": "test_card"},
    )
    paid.raise_for_status()
    return order_id


def _attack_action(path: str, method: str, token: str | None, payload: dict[str, object] | None) -> dict[str, object]:
    action: dict[str, object] = {
        "session": "attacker",
        "method": method,
        "path": path,
        "headers": ([{"name": "Authorization", "value": f"Bearer {token}"}] if token else []),
    }
    if payload is not None:
        action["body_json"] = json.dumps(payload, separators=(",", ":"))
    return action


def run_target(number: str) -> dict[str, object]:
    module_id = TARGETS[number]
    trial_id = uuid4().hex
    target = prepare_isolated_ruby_target(
        module_id, trial_id, normal_traffic_seed=0, public_api_prefix="/api"
    )
    gateway = None
    try:
        if target.runtime is None:
            raise RuntimeError("isolated runtime was not prepared")
        with httpx.Client(base_url=target.runtime.public_origin, timeout=20) as client:
            role = "seller_staff" if number == "25" else "support_staff" if number == "28" else "customer"
            account = next(item for item in target.accounts if item["role"] == role)
            token = _login(client, account)
            order_id = _paid_order(client, token) if number in {"26", "29"} else None
            if number == "25":
                path, method = "/api/seller/reports/exports", "POST"
                payload = {
                    "reports": ["sales-summary", "orders", "inventory"],
                    "idempotency_key": "outcome-25-seven",
                }
            elif number == "26":
                path, method = "/api/promotions/WELCOME500/redemptions", "POST"
                payload = {"order_id": order_id}
            elif number == "28":
                listed = client.get(
                    "/api/support/audit-events",
                    headers={"Authorization": f"Bearer {token}"},
                )
                listed.raise_for_status()
                audit_id = str(listed.json()[0]["id"])
                path, method = f"/api/support/audit-events/{audit_id}", "DELETE"
                payload = None
            else:
                path, method = "/api/integrations/partner/shipment-events", "POST"
                payload = {
                    "order_id": order_id,
                    "shipment_status": "packed",
                    "event_id": "outcome-29-forged-0001",
                    "occurred_at": int(time.time()) - 900,
                }
                # An expired, unsigned status change is unauthorized in the fixed variant.
                token = None

            adapter = StateTestAdapter(path)
            gateway = InlineDefenseGateway(
                upstream_origin=target.runtime.public_origin,
                trial_id=trial_id,
                adapter=adapter,
                identity={"defense_id": "isolated-scripted-state-test"},
                request_timeout_seconds=30,
            )
            target.executor.rebase(gateway.origin)
            action = _attack_action(path, method, token, payload)

            setup_statuses = []
            adapter.mode = "pass"
            if number == "25":
                for index in range(6):
                    setup = _attack_action(
                        path, method, token,
                        {**payload, "idempotency_key": f"outcome-25-setup-{index}"},
                    )
                    setup_statuses.append(target.executor.execute_http(setup)["status"])
            elif number == "26":
                setup_statuses.append(target.executor.execute_http(action)["status"])
            if target.evaluate()["objective_achieved"]:
                raise AssertionError("the setup already met the attack objective")

            adapter.mode = "block"
            blocked = target.executor.execute_http(action)
            blocked_verdict = target.evaluate()
            if number == "26":
                check = client.get(
                    "/api/orders",
                    headers={"Authorization": f"Bearer {token}"},
                )
                check.raise_for_status()
                state_after_block = next(item for item in check.json() if item["id"] == order_id)["total_cents"]
            elif number == "28":
                check = client.get(
                    "/api/support/audit-events",
                    headers={"Authorization": f"Bearer {token}"},
                )
                check.raise_for_status()
                state_after_block = audit_id in {item["id"] for item in check.json()}
            elif number == "29":
                check = client.get(
                    "/api/orders",
                    headers={"Authorization": f"Bearer {_login(client, account)}"},
                )
                check.raise_for_status()
                state_after_block = next(item for item in check.json() if item["id"] == order_id)["status"]
            else:
                state_after_block = None

            adapter.mode = "replace"
            adapter.last_upstream_status = None
            changed = target.executor.execute_http(action)
            changed_verdict = target.evaluate()
            if number == "28":
                check = client.get(
                    "/api/support/audit-events",
                    headers={"Authorization": f"Bearer {token}"},
                )
                check.raise_for_status()
                state_after_change = audit_id in {item["id"] for item in check.json()}
            elif number == "29":
                check = client.get(
                    "/api/orders",
                    headers={"Authorization": f"Bearer {_login(client, account)}"},
                )
                check.raise_for_status()
                state_after_change = next(item for item in check.json() if item["id"] == order_id)["status"]
            elif number == "26":
                check = client.get(
                    "/api/orders",
                    headers={"Authorization": f"Bearer {token}"},
                )
                check.raise_for_status()
                state_after_change = next(item for item in check.json() if item["id"] == order_id)["total_cents"]
            elif number == "25":
                state_after_change = json.loads(adapter.last_original_body or b"{}").get("pending_count")
            else:
                state_after_change = None

            return {
                "target": number,
                "module_id": module_id,
                "trial_id": trial_id,
                "setup_statuses": setup_statuses,
                "blocked": {
                    "status": blocked["status"],
                    "objective_achieved": blocked_verdict["objective_achieved"],
                    "state": state_after_block,
                },
                "response_replaced": {
                    "status": changed["status"],
                    "upstream_status": adapter.last_upstream_status,
                    "objective_achieved": changed_verdict["objective_achieved"],
                    "state": state_after_change,
                },
                "gateway_metrics": {
                    key: gateway.metrics()[key]
                    for key in ("observed_requests", "blocked_requests", "upstream_requests", "modified_responses", "defense_errors")
                },
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
    expected_setup = [202] * 6 if args.target == "25" else [200] if args.target == "26" else []
    valid = (
        result["setup_statuses"] == expected_setup
        and result["blocked"]["status"] == 403
        and not result["blocked"]["objective_achieved"]
        and result["response_replaced"]["status"] == 200
        and result["response_replaced"]["upstream_status"] == {"25": 202, "26": 200, "28": 204, "29": 200}[args.target]
        and result["response_replaced"]["objective_achieved"]
        and result["gateway_metrics"]["defense_errors"] == 0
    )
    if args.target == "28":
        valid = valid and result["blocked"]["state"] is True and result["response_replaced"]["state"] is False
    elif args.target == "29":
        valid = valid and result["blocked"]["state"] == "paid" and result["response_replaced"]["state"] == "packed"
    elif args.target == "26":
        valid = valid and result["response_replaced"]["state"] < result["blocked"]["state"]
    elif args.target == "25":
        valid = valid and result["response_replaced"]["state"] == 7
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
