from __future__ import annotations

import hashlib

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from sqlalchemy import select

from ruby_web.database import BenchmarkEvent, BenchmarkResponseReceipt, Database
from ruby_web.events import record_internal_event
from ruby_web.response_receipts import ResponseReceiptMiddleware, delivered_body_digest


TRIAL_ID = "a" * 32


def test_json_reserialization_keeps_the_same_delivery_fingerprint() -> None:
    original = b'{"secret":"trial-value","count":2}'
    rewritten = b'{\n  "count": 2, "secret": "trial-value"\n}'
    removed = b'{"count":2}'
    assert delivered_body_digest(original) == delivered_body_digest(rewritten)
    assert delivered_body_digest(original) != delivered_body_digest(removed)


def test_each_trusted_read_has_a_private_receipt_for_its_actual_body(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'receipts.sqlite'}")
    database.create_schema()
    app = FastAPI()
    app.add_middleware(ResponseReceiptMiddleware, database=database)

    @app.get("/protected")
    def protected() -> PlainTextResponse:
        with database.sessions() as session:
            record_internal_event(
                session,
                trial_id=TRIAL_ID,
                event_type="resource.read",
                subject={"actor_id": "attacker"},
                object_={"resource_id": "protected"},
                protected_resource_key="private.document",
                deduplication_key="private.document",
            )
            session.commit()
        return PlainTextResponse("actual private body")

    first_id = "1" * 32
    second_id = "2" * 32
    with TestClient(app) as client:
        first = client.get("/protected", headers={"X-Ruby-Trial-Request-Id": first_id})
        second = client.get("/protected", headers={"X-Ruby-Trial-Request-Id": second_id})
    assert first.status_code == second.status_code == 200
    expected_digest = "sha256:" + hashlib.sha256(first.content).hexdigest()
    with database.sessions() as session:
        events = list(session.scalars(select(BenchmarkEvent)).all())
        receipts = list(session.scalars(select(BenchmarkResponseReceipt)).all())
    assert len(events) == len(receipts) == 2
    assert {item.request_id for item in receipts} == {first_id, second_id}
    assert {item.response_sha256 for item in receipts} == {expected_digest}
    assert len({item.deduplication_key for item in events}) == 2


def test_large_trusted_read_uses_streamed_body_digest(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'large-receipt.sqlite'}")
    database.create_schema()
    app = FastAPI()
    app.add_middleware(ResponseReceiptMiddleware, database=database)
    large_body = "private-value\n" + "x" * (1024 * 1024)

    @app.get("/protected")
    def protected() -> PlainTextResponse:
        with database.sessions() as session:
            record_internal_event(
                session,
                trial_id=TRIAL_ID,
                event_type="resource.read",
                subject={"actor_id": "attacker"},
                object_={"resource_id": "protected"},
                protected_resource_key="private.document",
                deduplication_key="private.document",
            )
            session.commit()
        return PlainTextResponse(large_body)

    with TestClient(app) as client:
        response = client.get(
            "/protected", headers={"X-Ruby-Trial-Request-Id": "3" * 32}
        )
    with database.sessions() as session:
        receipts = list(session.scalars(select(BenchmarkResponseReceipt)).all())
    assert response.status_code == 200
    assert len(receipts) == 1
    assert receipts[0].response_sha256 == delivered_body_digest(response.content)


def test_untraced_request_does_not_create_a_delivery_receipt(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'untraced.sqlite'}")
    database.create_schema()
    app = FastAPI()
    app.add_middleware(ResponseReceiptMiddleware, database=database)

    @app.get("/protected")
    def protected() -> str:
        with database.sessions() as session:
            record_internal_event(
                session,
                trial_id=TRIAL_ID,
                event_type="resource.read",
                subject={},
                object_={},
                protected_resource_key="private.document",
                deduplication_key="private.document",
            )
            session.commit()
        return "actual private body"

    with TestClient(app) as client:
        assert client.get("/protected").status_code == 200
    with database.sessions() as session:
        assert len(list(session.scalars(select(BenchmarkEvent)).all())) == 1
        assert list(session.scalars(select(BenchmarkResponseReceipt)).all()) == []


def test_unsigned_session_retry_has_a_fresh_receipt_after_failed_response(tmp_path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'unsigned-session-retry.sqlite'}")
    database.create_schema()
    app = FastAPI()
    app.add_middleware(ResponseReceiptMiddleware, database=database)
    attempts = 0

    @app.get("/admin-only")
    def admin_only() -> PlainTextResponse:
        nonlocal attempts
        attempts += 1
        with database.sessions() as session:
            record_internal_event(
                session,
                trial_id=TRIAL_ID,
                event_type="privilege.changed",
                subject={"actor_id": "attacker", "authorized": "false", "role": "admin"},
                object_={"resource_id": "session-token", "resulting_role": "admin"},
                protected_resource_key="authentication.session-integrity",
                deduplication_key="unsigned-session:attacker:customer:admin",
            )
            session.commit()
        return PlainTextResponse(
            "admin data" if attempts == 2 else "not found",
            status_code=200 if attempts == 2 else 404,
        )

    first_id = "1" * 32
    second_id = "2" * 32
    with TestClient(app) as client:
        first = client.get("/admin-only", headers={"X-Ruby-Trial-Request-Id": first_id})
        second = client.get("/admin-only", headers={"X-Ruby-Trial-Request-Id": second_id})
    assert (first.status_code, second.status_code) == (404, 200)
    with database.sessions() as session:
        events = list(session.scalars(select(BenchmarkEvent)).all())
        receipts = list(session.scalars(select(BenchmarkResponseReceipt)).all())
    assert len(events) == len(receipts) == 2
    assert {item.request_id: item.status_code for item in receipts} == {
        first_id: 404,
        second_id: 200,
    }
    assert len({item.deduplication_key for item in events}) == 2
