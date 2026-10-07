from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ruby_web.config import Settings
from ruby_web.database import Database, User
from ruby_web.main import create_app
from ruby_web.seed import seed_password
from ruby_web.services import MemoryServices


def test_additional_public_origins_require_literal_http_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "RUBY_WEB_PUBLIC_ORIGINS",
        "http://158.247.253.127:3020, http://158.247.253.127",
    )
    selected = Settings.from_environment()
    assert selected.allows_public_origin("http://158.247.253.127:3020")
    assert selected.allows_public_origin("http://158.247.253.127")
    assert selected.allows_public_origin(selected.public_origin)
    assert not selected.allows_public_origin("http://158.247.253.127:3021")

    for invalid in (
        "http://*.example.com",
        "http://example.com/path",
        "http://user@example.com",
        "https://example.com?x=1",
        "http://example.com:broken",
    ):
        monkeypatch.setenv("RUBY_WEB_PUBLIC_ORIGINS", invalid)
        with pytest.raises(RuntimeError):
            Settings.from_environment()


def test_normal_role_forms_accept_protected_and_direct_origins_only() -> None:
    support_id = "00000000-0000-4000-8000-000000000003"
    with tempfile.TemporaryDirectory() as directory:
        database = Database(f"sqlite:///{Path(directory) / 'public-origins.sqlite3'}")
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
            public_origin="http://158.247.253.127:3020",
            additional_public_origins=frozenset({"http://158.247.253.127"}),
        )
        app = create_app(
            selected,
            database=database,
            session_store=memory,
            object_store=memory,
            job_queue=memory,
        )
        with TestClient(app) as client:
            login = client.post(
                "/api/auth/login",
                json={
                    "email": "admin@ruby.local",
                    "password": seed_password("admin@ruby.local"),
                },
            )
            assert login.status_code == 200
            authorization = {"Authorization": f"Bearer {login.json()['token']}"}
            for path in ("role-form", "remembered-role-form"):
                for origin, role in (
                    ("http://158.247.253.127:3020", "support_staff"),
                    ("http://158.247.253.127", "admin"),
                ):
                    response = client.post(
                        f"/api/admin/users/{support_id}/{path}",
                        headers={**authorization, "Origin": origin},
                        data={"role": role},
                    )
                    assert response.status_code == 200, response.text
                rejected = client.post(
                    f"/api/admin/users/{support_id}/{path}",
                    headers={**authorization, "Origin": "http://attacker.example"},
                    data={"role": "customer"},
                )
                assert rejected.status_code == 403
                with database.sessions() as session:
                    assert session.get(User, support_id).role == "admin"
        database.engine.dispose()
