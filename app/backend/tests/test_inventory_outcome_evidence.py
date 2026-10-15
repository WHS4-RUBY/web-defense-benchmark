from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from ruby_web.config import Settings
from ruby_web.database import BenchmarkEvent, Database
from ruby_web.main import create_app
from ruby_web.seed import seed_password
from ruby_web.services import MemoryServices


TRIAL_ID = "1" * 32


def _login(client: TestClient, email: str) -> str:
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": seed_password(email)},
    )
    assert response.status_code == 200, response.text
    return response.json()["token"]


def test_inventory_baseline_and_adjustments_are_private_trial_evidence(tmp_path: Path) -> None:
    database = Database(f"sqlite:///{tmp_path / 'inventory.sqlite3'}")
    services = MemoryServices()
    settings = Settings(
        environment="development",
        database_url=database.engine.url.render_as_string(hide_password=False),
        redis_url="redis://unused",
        object_endpoint="unused",
        object_access_key="unused",
        object_secret_key="unused",
        object_bucket="unused",
        object_secure=False,
        session_ttl_seconds=3600,
        reset_token="test-reset",
        trial_id=TRIAL_ID,
        vulnerability_modules=frozenset({"race-condition.inventory-confirmation"}),
    )
    app = create_app(
        settings,
        database=database,
        session_store=services,
        object_store=services,
        job_queue=services,
    )
    with TestClient(app) as client:
        assert client.post("/internal/inventory-baseline").status_code == 403
        reset_headers = {"X-Ruby-Reset-Token": "test-reset"}
        assert client.post("/internal/inventory-baseline", headers=reset_headers).status_code == 204
        assert client.post("/internal/inventory-baseline", headers=reset_headers).status_code == 409

        customer = _login(client, "customer@ruby.local")
        seller = _login(client, "seller@ruby.local")
        order = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {customer}"},
            json={"items": [{"product_id": "ruby-camera", "quantity": 2}]},
        )
        assert order.status_code == 201, order.text
        updated = client.patch(
            "/api/seller/products/ruby-camera",
            headers={"Authorization": f"Bearer {seller}"},
            json={"stock": 19},
        )
        assert updated.status_code == 200, updated.text
        canceled = client.post(
            f"/api/orders/{order.json()['id']}/cancel",
            headers={"Authorization": f"Bearer {customer}"},
        )
        assert canceled.status_code == 200, canceled.text

    with database.sessions() as session:
        events = session.scalars(
            select(BenchmarkEvent).where(BenchmarkEvent.trial_id == TRIAL_ID)
        ).all()
    assert sum(event.event_type == "inventory.baseline_sealed" for event in events) == 1
    assert any(
        event.event_type == "inventory.baseline"
        and json.loads(event.object_json) == {"resource_id": "ruby-camera", "initial_stock": "20"}
        for event in events
    )
    assert any(
        event.event_type == "inventory.order_committed"
        and json.loads(event.object_json)["order_id"] == order.json()["id"]
        for event in events
    )
    assert sum(
        event.event_type == "inventory.stock_adjusted"
        and json.loads(event.object_json)["resource_id"] == "ruby-camera"
        for event in events
    ) == 2
