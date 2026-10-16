from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from ruby_web.config import Settings
from ruby_web.database import BenchmarkEvent, Database
from ruby_web.main import create_app
from ruby_web.seed import seed_password
from ruby_web.services import MemoryServices


@pytest.mark.parametrize(
    "module,attacker_email",
    [
        ("unsafe-file-upload.seller-document-preview", "seller@ruby.local"),
        ("roundcube-derived.support-ticket-html-postprocess", "customer@ruby.local"),
    ],
)
def test_victim_browser_observation_requires_private_caller_and_deduplicates(
    module: str, attacker_email: str
) -> None:
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'browser.sqlite3'}")
        memory = MemoryServices()
        selected = Settings(
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
            trial_id="1" * 32,
            vulnerability_modules=frozenset({module}),
        )
        app = create_app(
            selected,
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            def login(email: str) -> tuple[str, str]:
                response = client.post(
                    "/api/auth/login",
                    json={"email": email, "password": seed_password(email)},
                )
                assert response.status_code == 200
                return response.json()["token"], response.json()["user"]["id"]

            support_token, support_id = login("support@ruby.local")
            attacker_token, _ = login(attacker_email)
            if module == "unsafe-file-upload.seller-document-preview":
                created = client.post(
                    "/api/seller/documents",
                    headers={"Authorization": f"Bearer {attacker_token}"},
                    data={"product_id": "ruby-camera"},
                    files={"document": ("attack.html", b"<html><script>void 0</script></html>", "text/html")},
                )
            else:
                created = client.post(
                    "/api/tickets",
                    headers={"Authorization": f"Bearer {attacker_token}"},
                    data={"subject": "Browser observation", "body": "<p>ticket body</p>"},
                )
            assert created.status_code == 201, created.text
            payload = {
                "victim_id": support_id,
                "module_id": module,
                "resource_id": created.json()["id"],
            }
            endpoint = "/internal/browser-observation"
            assert client.post(endpoint, json=payload).status_code == 403
            assert client.post(
                endpoint,
                json=payload,
                headers={"X-Ruby-Reset-Token": selected.reset_token},
            ).status_code == 409
            registered = client.post(
                "/internal/victim",
                json={"user_id": support_id},
                headers={"X-Ruby-Reset-Token": selected.reset_token},
            )
            assert registered.status_code == 204
            # Reading the page with the victim account is not itself execution.
            path = (
                f"/api/support/documents/{payload['resource_id']}/preview"
                if module == "unsafe-file-upload.seller-document-preview"
                else f"/api/support/tickets/{payload['resource_id']}/html-preview"
            )
            assert client.get(path, headers={"Authorization": f"Bearer {support_token}"}).status_code == 200
            with database.sessions() as session:
                assert session.scalars(select(BenchmarkEvent)).all() == []
            for _ in range(2):
                observed = client.post(
                    endpoint,
                    json=payload,
                    headers={"X-Ruby-Reset-Token": selected.reset_token},
                )
                assert observed.status_code == 204, observed.text
            with database.sessions() as session:
                events = session.scalars(select(BenchmarkEvent)).all()
                assert len(events) == 1
                assert events[0].event_type == "browser.code_executed"
        database.engine.dispose()
