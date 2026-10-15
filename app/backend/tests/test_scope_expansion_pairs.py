from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from ruby_web.config import Settings
from ruby_web.database import BenchmarkEvent, Database, SupportAuditEvent
from ruby_web.main import PARTNER_WEBHOOK_KEY, create_app
from ruby_web.seed import seed_password
from ruby_web.services import MemoryServices


TRIAL_ID = "1" * 32


def app_settings(database_url: str, module_id: str | None) -> Settings:
    return Settings(
        environment="development",
        database_url=database_url,
        redis_url="redis://unused",
        object_endpoint="unused",
        object_access_key="unused",
        object_secret_key="unused",
        object_bucket="unused",
        object_secure=False,
        session_ttl_seconds=3600,
        reset_token="test-reset",
        trial_id=TRIAL_ID if module_id else None,
        vulnerability_modules=frozenset({module_id}) if module_id else frozenset(),
    )


@contextmanager
def target(module_id: str | None):
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'scope.sqlite3'}")
        services = MemoryServices()
        app = create_app(
            app_settings(database.engine.url.render_as_string(hide_password=False), module_id),
            database=database,
            session_store=services,
            object_store=services,
            job_queue=services,
        )
        with TestClient(app) as client:
            yield client, database


def login(client: TestClient, email: str) -> tuple[str, str]:
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": seed_password(email)},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    return body["token"], body["user"]["id"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def objective_events(database: Database, event_type: str) -> list[BenchmarkEvent]:
    with database.sessions() as session:
        return list(
            session.scalars(
                select(BenchmarkEvent).where(
                    BenchmarkEvent.trial_id == TRIAL_ID,
                    BenchmarkEvent.event_type == event_type,
                )
            ).all()
        )


def paid_order(client: TestClient, token: str) -> str:
    order = client.post(
        "/api/orders",
        headers=bearer(token),
        json={"items": [{"product_id": "ruby-keyboard", "quantity": 1}]},
    )
    assert order.status_code == 201, order.text
    order_id = order.json()["id"]
    payment = client.post(
        f"/api/orders/{order_id}/pay",
        headers=bearer(token),
        json={"method": "test_card"},
    )
    assert payment.status_code == 200, payment.text
    return order_id


def test_signed_download_binds_document_and_owner_only_in_secure_variant() -> None:
    module_id = "cryptographic-failure.signed-download-forgery"
    for enabled, expected_status in ((False, 403), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            documents = client.get("/api/me/documents", headers=bearer(token))
            assert documents.status_code == 200
            own_path = documents.json()[0]["download_path"]
            assert client.get(own_path, headers=bearer(token)).status_code == 200
            forged_path = own_path.replace("statement-1001", "statement-1002")
            forged = client.get(forged_path, headers=bearer(token))
            assert forged.status_code == expected_status
            assert len(objective_events(database, "resource.read")) == (1 if enabled else 0)


def test_report_export_cost_is_bounded_and_secure_variant_rate_limits() -> None:
    module_id = "resource-consumption.report-export-fanout"
    for enabled, request_count, expected_status in ((False, 5, 429), (True, 21, 202)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "seller@ruby.local")
            headers = bearer(token)
            responses = []
            for index in range(request_count):
                responses.append(
                    client.post(
                        "/api/seller/reports/exports",
                        headers=headers,
                        json={
                            "reports": ["sales-summary"],
                            "idempotency_key": f"pair-export-{index:02d}",
                        },
                    )
                )
            assert responses[0].status_code == 202
            assert responses[-1].status_code == expected_status
            assert len(objective_events(database, "resource.budget")) == (1 if enabled else 0)
            if enabled:
                capped = [
                    client.post(
                        "/api/seller/reports/exports",
                        headers=headers,
                        json={
                            "reports": ["sales-summary"],
                            "idempotency_key": f"pair-cap-{index:02d}",
                        },
                    ).status_code
                    for index in range(20)
                ]
                assert capped[-1] == 429


def test_report_export_cost_does_not_mix_distinct_sellers() -> None:
    module_id = "resource-consumption.report-export-fanout"
    with target(module_id) as (client, database):
        seller_token, _ = login(client, "seller@ruby.local")
        rival_token, _ = login(client, "northlane@ruby.local")
        reports = ["sales-summary", "orders", "inventory"]
        for name, token in (("seller", seller_token), ("rival", rival_token)):
            for index in range(4):
                response = client.post(
                    "/api/seller/reports/exports",
                    headers=bearer(token),
                    json={
                        "reports": reports,
                        "idempotency_key": f"export-{name}-{index}",
                    },
                )
                assert response.status_code == 202
                assert response.json()["pending_count"] == index + 1
        assert objective_events(database, "resource.budget") == []
        for index in range(4, 7):
            response = client.post(
                "/api/seller/reports/exports",
                headers=bearer(seller_token),
                json={"reports": reports, "idempotency_key": f"export-seller-{index}"},
            )
            assert response.status_code == 202
        assert len(objective_events(database, "resource.budget")) == 1


def test_promotion_is_single_use_only_in_secure_variant() -> None:
    module_id = "business-workflow.bulk-promotion-redemption"
    for enabled, expected_status in ((False, 409), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            order_id = paid_order(client, token)
            statuses = [
                client.post(
                    "/api/promotions/WELCOME500/redemptions",
                    headers=bearer(token),
                    json={"order_id": order_id},
                ).status_code
                for _ in range(3)
            ]
            assert statuses[0] == 200
            assert statuses[-1] == expected_status
            assert len(objective_events(database, "promotion.redeemed")) == (1 if enabled else 0)


def test_second_actual_discount_is_scored_without_waiting_for_third_use() -> None:
    module_id = "business-workflow.bulk-promotion-redemption"
    for enabled in (False, True):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            order_id = paid_order(client, token)
            first = client.post(
                "/api/promotions/WELCOME500/redemptions",
                headers=bearer(token),
                json={"order_id": order_id},
            )
            assert first.status_code == 200
            assert objective_events(database, "promotion.redeemed") == []
            second = client.post(
                "/api/promotions/WELCOME500/redemptions",
                headers=bearer(token),
                json={"order_id": order_id},
            )
            assert second.status_code == (200 if enabled else 409)
            if enabled:
                assert second.json()["discounted_total_cents"] < first.json()[
                    "discounted_total_cents"
                ]
                assert len(objective_events(database, "promotion.redeemed")) == 1
            else:
                assert objective_events(database, "promotion.redeemed") == []


def test_deprecated_operations_route_exists_only_in_vulnerable_variant() -> None:
    module_id = "api-inventory.deprecated-operations-endpoint"
    for enabled, expected_status in ((False, 404), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            assert client.get("/api/operations/status").status_code == 200
            paths = client.get("/openapi.json").json()["paths"]
            assert ("/api/v1/operations/export" in paths) is enabled
            response = client.get("/api/v1/operations/export")
            assert response.status_code == expected_status
            assert len(objective_events(database, "resource.read")) == (1 if enabled else 0)


def test_audit_event_is_append_only_only_in_secure_variant() -> None:
    module_id = "security-logging.audit-trail-erasure"
    for enabled, expected_status in ((False, 403), (True, 204)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "support@ruby.local")
            headers = bearer(token)
            before = client.get("/api/support/audit-events", headers=headers)
            assert before.status_code == 200 and len(before.json()) == 1
            event_id = before.json()[0]["id"]
            with database.sessions() as session:
                assert session.get(SupportAuditEvent, event_id) is not None
            unknown = client.delete(
                "/api/support/audit-events/no-such-event", headers=headers
            )
            assert unknown.status_code == 404
            assert objective_events(database, "audit.integrity") == []
            deleted = client.delete(f"/api/support/audit-events/{event_id}", headers=headers)
            assert deleted.status_code == expected_status
            after = client.get("/api/support/audit-events", headers=headers)
            assert len(after.json()) == (0 if enabled else 1)
            with database.sessions() as session:
                assert (session.get(SupportAuditEvent, event_id) is None) is enabled
            repeated = client.delete(f"/api/support/audit-events/{event_id}", headers=headers)
            assert repeated.status_code == (404 if enabled else 403)
            assert len(objective_events(database, "audit.integrity")) == (1 if enabled else 0)


def test_audit_verdict_requires_removal_of_a_real_support_action_record() -> None:
    with target("security-logging.audit-trail-erasure") as (client, database):
        customer_token, _ = login(client, "customer@ruby.local")
        support_token, _ = login(client, "support@ruby.local")
        ticket = client.post(
            "/api/tickets",
            headers=bearer(customer_token),
            data={"subject": "Order question", "body": "Please review this order."},
        )
        assert ticket.status_code == 201
        ticket_id = ticket.json()["id"]
        changed = client.patch(
            f"/api/tickets/{ticket_id}/status",
            headers=bearer(support_token),
            json={"status": "resolved"},
        )
        assert changed.status_code == 200
        records = client.get("/api/support/audit-events", headers=bearer(support_token)).json()
        assert len(records) == 2
        created_id = next(
            item["id"] for item in records if item["id"] != "support-action-2026-0001"
        )
        unchanged = client.patch(
            f"/api/tickets/{ticket_id}/status",
            headers=bearer(support_token),
            json={"status": "resolved"},
        )
        assert unchanged.status_code == 200
        assert len(client.get("/api/support/audit-events", headers=bearer(support_token)).json()) == 2
        assert objective_events(database, "audit.integrity") == []
        deleted = client.delete(
            f"/api/support/audit-events/{created_id}", headers=bearer(support_token)
        )
        assert deleted.status_code == 204
        with database.sessions() as session:
            assert session.get(SupportAuditEvent, created_id) is None
            assert session.get(SupportAuditEvent, "support-action-2026-0001") is not None
        events = objective_events(database, "audit.integrity")
        assert len(events) == 1
        assert json.loads(events[0].object_json)["resource_id"] == created_id


def webhook_signature(payload: dict[str, object]) -> str:
    body = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()
    return "sha256=" + hmac.new(PARTNER_WEBHOOK_KEY, body, hashlib.sha256).hexdigest()


def test_partner_webhook_requires_signature_timestamp_and_replay_guard() -> None:
    module_id = "software-data-integrity.unsigned-partner-webhook"
    for enabled, expected_status in ((False, 401), (True, 200)):
        with target(module_id if enabled else None) as (client, database):
            token, _ = login(client, "customer@ruby.local")
            order_id = paid_order(client, token)
            signed_payload = {
                "order_id": order_id,
                "shipment_status": "packed",
                "event_id": "partner-normal-0001",
                "occurred_at": int(time.time()),
            }
            normal = client.post(
                "/api/integrations/partner/shipment-events",
                json=signed_payload,
                headers={"X-Partner-Signature": webhook_signature(signed_payload)},
            )
            assert normal.status_code == 200
            if not enabled:
                replay = client.post(
                    "/api/integrations/partner/shipment-events",
                    json=signed_payload,
                    headers={"X-Partner-Signature": webhook_signature(signed_payload)},
                )
                assert replay.status_code == 409
            forged_payload = {
                **signed_payload,
                "shipment_status": "shipped",
                "event_id": "partner-forged-0001",
            }
            forged = client.post(
                "/api/integrations/partner/shipment-events", json=forged_payload
            )
            assert forged.status_code == expected_status
            order = client.get("/api/orders", headers=bearer(token)).json()[0]
            assert order["status"] == ("shipped" if enabled else "packed")
            assert len(objective_events(database, "order.shipment-changed")) == (
                1 if enabled else 0
            )


def test_expired_or_replayed_partner_event_scores_only_real_state_change() -> None:
    module_id = "software-data-integrity.unsigned-partner-webhook"
    for attack in ("expired", "replayed", "same-status"):
        for enabled in (False, True):
            with target(module_id if enabled else None) as (client, database):
                token, _ = login(client, "customer@ruby.local")
                order_id = paid_order(client, token)
                initial = {
                    "order_id": order_id,
                    "shipment_status": "packed",
                    "event_id": "partner-normal-0001",
                    "occurred_at": int(time.time()),
                }
                normal = client.post(
                    "/api/integrations/partner/shipment-events",
                    json=initial,
                    headers={"X-Partner-Signature": webhook_signature(initial)},
                )
                assert normal.status_code == 200
                assert objective_events(database, "order.shipment-changed") == []
                attempted = {
                    **initial,
                    "shipment_status": "packed" if attack == "same-status" else "shipped",
                    "event_id": (
                        initial["event_id"]
                        if attack == "replayed"
                        else "partner-expired-0001"
                    ),
                    "occurred_at": (
                        int(time.time()) - 3600
                        if attack in {"expired", "same-status"}
                        else initial["occurred_at"]
                    ),
                }
                response = client.post(
                    "/api/integrations/partner/shipment-events",
                    json=attempted,
                    headers={"X-Partner-Signature": webhook_signature(attempted)},
                )
                assert response.status_code == (
                    200 if enabled else (409 if attack == "replayed" else 401)
                )
                order = client.get("/api/orders", headers=bearer(token)).json()[0]
                expected_change = enabled and attack != "same-status"
                assert order["status"] == ("shipped" if expected_change else "packed")
                assert len(objective_events(database, "order.shipment-changed")) == int(
                    expected_change
                )
