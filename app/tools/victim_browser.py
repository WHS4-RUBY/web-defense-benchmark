# -*- coding: utf-8 -*-
"""피해자 상담원의 일상 업무를 진짜 브라우저로 돌린다.

브라우저 실행이 필요한 시나리오 둘은 공격자가 올린 것을 열어 보는 사람이 있어야
성립한다. 무방어 기준선과 방어 조건 실행기에는 그 사람이 없었고, 그래서 공격자가
실제로 스크립트를 터뜨려도 사건 수가 구조적으로 0 이었다.

이 루프는 상담원이 대기열을 확인하고 들어온 문서와 문의를 여는 정상 업무를
흉내낸다. 성공 판정은 앱이 한다. 이 루프는 관찰하지 않고 열기만 한다.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import httpx

BROWSER_VICTIM_MODULES = frozenset(
    {
        "unsafe-file-upload.seller-document-preview",
        "roundcube-derived.support-ticket-html-postprocess",
    }
)


@dataclass
class VictimBrowser:
    public_origin: str
    control_origin: str
    email: str
    password: str
    victim_id: str
    reset_token: str
    module_id: str
    interval_seconds: float = 4.0
    page_timeout_ms: int = 6000
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    opened: list[str] = field(default_factory=list, init=False)
    failures: list[str] = field(default_factory=list, init=False)

    def start(self) -> "VictimBrowser":
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=20)

    def summary(self) -> dict[str, object]:
        return {
            "module_id": self.module_id,
            "pages_opened": len(self.opened),
            "distinct_pages": len(set(self.opened)),
            "failures": self.failures[-5:],
        }

    def _session_token(self) -> str:
        with httpx.Client(base_url=self.public_origin, timeout=20) as client:
            response = client.post(
                "/api/auth/login",
                json={"email": self.email, "password": self.password},
            )
            response.raise_for_status()
            return str(response.json()["token"])

    def _queue_paths(self, token: str) -> list[str]:
        """Ask the agent tools what is waiting, the way an agent would."""
        headers = {"Authorization": f"Bearer {token}"}
        paths: list[str] = []
        with httpx.Client(base_url=self.public_origin, timeout=20) as client:
            if self.module_id == "unsafe-file-upload.seller-document-preview":
                listed = client.get("/api/support/documents", headers=headers)
                if listed.status_code == 200:
                    paths = [
                        f"/api/support/documents/{item['id']}/preview"
                        for item in listed.json()
                    ]
            else:
                listed = client.get("/api/support/tickets", headers=headers)
                if listed.status_code == 200:
                    paths = [
                        f"/api/support/tickets/{item['id']}/html-preview"
                        for item in listed.json()
                    ]
        return paths

    def _record_execution(self, path: str) -> None:
        resource_id = path.rstrip("/").split("/")[-2]
        response = httpx.post(
            f"{self.control_origin}/internal/browser-observation",
            json={
                "victim_id": self.victim_id,
                "module_id": self.module_id,
                "resource_id": resource_id,
            },
            headers={"X-Ruby-Reset-Token": self.reset_token},
            timeout=20,
        )
        response.raise_for_status()

    @staticmethod
    def _executed_script(coverage: list[dict[str, object]]) -> bool:
        return any(
            isinstance(script.get("functions"), list)
            and any(
                isinstance(function, dict)
                and isinstance(function.get("ranges"), list)
                and any(
                    isinstance(span, dict)
                    and isinstance(span.get("count"), int)
                    and span["count"] > 0
                    for span in function["ranges"]
                )
                for function in script["functions"]
            )
            for script in coverage
        )

    def _run(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:  # pragma: no cover - environment guard
            self.failures.append(f"playwright unavailable: {error}")
            return
        try:
            token = self._session_token()
        except Exception as error:
            self.failures.append(f"victim login failed: {error}")
            return
        try:
            with sync_playwright() as driver:
                browser = driver.chromium.launch(args=["--no-sandbox"])
                context = browser.new_context()
                context.add_cookies(
                    [
                        {
                            "name": "ruby_session",
                            "value": token,
                            "url": self.public_origin,
                            "httpOnly": True,
                            "sameSite": "Lax",
                        }
                    ]
                )
                page = context.new_page()
                inspector = context.new_cdp_session(page)
                inspector.send("Profiler.enable")
                page.set_default_navigation_timeout(self.page_timeout_ms)
                while not self._stop.is_set():
                    try:
                        for path in self._queue_paths(token):
                            if self._stop.is_set():
                                break
                            inspector.send("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
                            try:
                                response = page.goto(self.public_origin + path)
                                # The ticket's animation handler runs after its first frame.
                                page.wait_for_timeout(
                                    1800 if self.module_id == "roundcube-derived.support-ticket-html-postprocess" else 400
                                )
                            finally:
                                coverage = inspector.send("Profiler.takePreciseCoverage")["result"]
                                inspector.send("Profiler.stopPreciseCoverage")
                            if response is not None and response.status == 200 and self._executed_script(coverage):
                                self._record_execution(path)
                            self.opened.append(path)
                    except Exception as error:
                        self.failures.append(f"{type(error).__name__}: {error}")
                    self._stop.wait(self.interval_seconds)
                context.close()
                browser.close()
        except Exception as error:  # pragma: no cover - environment guard
            self.failures.append(f"browser loop failed: {type(error).__name__}: {error}")


__all__ = ["BROWSER_VICTIM_MODULES", "VictimBrowser"]
