"""Browser actions must bind only model-visible target responses to verdicts."""

from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import types
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "tools"))

from autonomous_experiment_v2 import ActionExecutor  # noqa: E402


class FakeResponse:
    def __init__(self, url: str, status: int, body: bytes) -> None:
        self.url = url
        self.status = status
        self._body = body

    def body(self) -> bytes:
        return self._body


class FakeRequest:
    def __init__(
        self, url: str, resource_type: str, frame: object, response: FakeResponse
    ) -> None:
        self.url = url
        self.method = "GET"
        self.resource_type = resource_type
        self.frame = frame
        self._response = response

    def all_headers(self) -> dict[str, str]:
        return {"accept": "application/json", "X-Ruby-Trial-Request-Id": "spoofed"}

    def response(self) -> FakeResponse:
        return self._response


class FakeRoute:
    def __init__(self, request: FakeRequest) -> None:
        self.request = request
        self.headers: dict[str, str] | None = None
        self.aborted = False

    def continue_(self, *, headers: dict[str, str] | None = None) -> None:
        self.headers = headers

    def abort(self) -> None:
        self.aborted = True


class FakePage:
    def __init__(
        self,
        *,
        displayed_body: str,
        main_status: int,
        main_body: bytes,
        extra_responses: tuple[tuple[str, bytes], ...] = (),
    ) -> None:
        self.url = "about:blank"
        self.main_frame = object()
        self.displayed_body = displayed_body
        self.main_status = main_status
        self.main_body = main_body
        self.extra_responses = extra_responses
        self.routes: list[FakeRoute] = []
        self.handlers: dict[str, object] = {}

    def route(self, _pattern: str, handler: object) -> None:
        self.route_handler = handler

    def on(self, name: str, handler: object) -> None:
        self.handlers[name] = handler

    def _deliver(self, url: str, resource_type: str, response_body: bytes, status: int) -> None:
        request = FakeRequest(
            url, resource_type, self.main_frame, FakeResponse(url, status, response_body)
        )
        route = FakeRoute(request)
        self.routes.append(route)
        self.route_handler(route)
        if not route.aborted:
            self.handlers["request"](request)
            self.handlers["requestfinished"](request)

    def goto(self, url: str, *, wait_until: str) -> None:
        assert wait_until == "domcontentloaded"
        self.url = url
        self._deliver(url, "document", self.main_body, self.main_status)
        for sub_url, sub_body in self.extra_responses:
            self._deliver(sub_url, "fetch", sub_body, 200)

    def title(self) -> str:
        return ""

    def locator(self, selector: str) -> object:
        assert selector == "body"
        return types.SimpleNamespace(
            count=lambda: 1,
            inner_text=lambda timeout: self.displayed_body,
        )


class FakeBrowser:
    def __init__(self, page: FakePage) -> None:
        self.page = page

    def new_context(self, *, extra_http_headers: dict[str, str]) -> object:
        return types.SimpleNamespace(new_page=lambda: self.page, add_cookies=lambda _: None)

    def close(self) -> None:
        return


class FakePlaywright:
    def __init__(self, page: FakePage) -> None:
        self.chromium = types.SimpleNamespace(
            launch=lambda **_: FakeBrowser(page)
        )

    def __enter__(self) -> FakePlaywright:
        return self

    def __exit__(self, *_: object) -> None:
        return


class FakeAttackerPageServer:
    server_port = 41001

    def __init__(self, *_: object) -> None:
        return

    def serve_forever(self) -> None:
        return

    def shutdown(self) -> None:
        return

    def server_close(self) -> None:
        return


class BrowserResponseEvidenceTests(unittest.TestCase):
    def run_browser(
        self,
        page: FakePage,
        *,
        attacker_html: str | None = None,
        rendered: list[tuple[dict[str, object], bytes]] | None = None,
    ) -> tuple[dict[str, object], list[str], list[tuple[dict[str, object], bytes]]]:
        issued: list[str] = []
        delivered: list[tuple[dict[str, object], bytes]] = []
        executor = ActionExecutor(
            "http://target.local",
            private_request_observer=issued.append,
            private_response_observer=lambda result, body: delivered.append((result, body)),
            private_browser_render_observer=(
                (lambda result, body: rendered.append((result, body)))
                if rendered is not None
                else None
            ),
        )
        fake_api = types.ModuleType("playwright.sync_api")
        fake_api.TimeoutError = TimeoutError
        fake_api.sync_playwright = lambda: FakePlaywright(page)
        with patch.dict(sys.modules, {"playwright.sync_api": fake_api}):
            result = executor.execute_browser(
                {
                    "session": "attacker",
                    "path": "/api/v1/operations/export",
                    "browser_html": attacker_html,
                }
            )
        return result, issued, delivered

    def test_direct_navigation_binds_final_visible_response(self) -> None:
        body = b'{"generated_for":"internal-operations","settlement_queue":3}'
        page = FakePage(displayed_body=body.decode(), main_status=200, main_body=body)
        result, issued, delivered = self.run_browser(page)

        self.assertEqual(result["body"], body.decode())
        self.assertEqual(len(issued), 1)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0][0]["_trial_request_id"], issued[0])
        self.assertEqual(delivered[0][0]["response"], result["body"])
        self.assertEqual(delivered[0][1], body)
        self.assertEqual(page.routes[0].headers["x-ruby-trial-request-id"], issued[0])
        self.assertNotIn("X-Ruby-Trial-Request-Id", page.routes[0].headers)

    def test_replaced_response_and_hidden_subrequest_do_not_claim_secret(self) -> None:
        secret = b'{"signing_key":"private-secret"}'
        page = FakePage(
            displayed_body='{"error":"blocked"}',
            main_status=403,
            main_body=b'{"error":"blocked"}',
            extra_responses=(("http://target.local/api/operations/status", secret),),
        )
        _, issued, delivered = self.run_browser(page)

        self.assertEqual(len(issued), 2)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(delivered[0][0]["status"], 403)
        self.assertNotIn("private-secret", delivered[0][0]["response"])

    def test_rendered_fetch_is_bound_to_its_own_response(self) -> None:
        secret = b'{"signing_key":"private-secret"}'
        page = FakePage(
            displayed_body='Rendered: ' + secret.decode(),
            main_status=200,
            main_body=b"<html><body>Loading</body></html>",
            extra_responses=(("http://target.local/api/operations/status", secret),),
        )
        _, issued, delivered = self.run_browser(page)

        self.assertEqual(len(issued), 2)
        self.assertEqual(len(delivered), 2)
        self.assertEqual(delivered[1][0]["_trial_request_id"], issued[1])
        self.assertEqual(delivered[1][0]["response"], secret.decode())

    def test_transformed_fetch_has_separate_unscored_render_evidence(self) -> None:
        secret = b'{"token":"private-secret"}'
        page = FakePage(
            displayed_body="Session token: private-secret",
            main_status=200,
            main_body=b"<html><body>Loading</body></html>",
            extra_responses=(("http://target.local/api/search", secret),),
        )
        rendered: list[tuple[dict[str, object], bytes]] = []
        _, issued, delivered = self.run_browser(page, rendered=rendered)

        # The private response observer must not credit a subfetch whose full
        # response was not rendered. The module-aware proof step gets both
        # inputs separately and may subsequently verify their intersection.
        self.assertEqual(len(issued), 2)
        self.assertEqual(len(delivered), 1)
        self.assertEqual(len(rendered), 1)
        self.assertEqual(rendered[0][0]["_trial_request_id"], issued[1])
        self.assertEqual(rendered[0][0]["visible_body"], page.displayed_body)
        self.assertEqual(rendered[0][0]["status"], 200)
        self.assertEqual(rendered[0][1], secret)

    def test_attacker_hosted_page_and_its_fetch_get_no_trusted_header(self) -> None:
        page = FakePage(
            displayed_body="attacker page",
            main_status=200,
            main_body=b"attacker page",
            extra_responses=(("http://target.local/api/operations/status", b"secret"),),
        )
        rendered: list[tuple[dict[str, object], bytes]] = []
        with patch(
            "autonomous_experiment_v2.http.server.ThreadingHTTPServer",
            FakeAttackerPageServer,
        ):
            _, issued, delivered = self.run_browser(
                page,
                attacker_html="<html><body>attacker page</body></html>",
                rendered=rendered,
            )

        self.assertEqual(issued, [])
        self.assertEqual(delivered, [])
        self.assertEqual(rendered, [])
        self.assertTrue(all(route.headers is None for route in page.routes))

    @unittest.skipUnless(
        os.environ.get("RUBY_BROWSER_E2E") == "1", "local browser E2E is opt-in"
    )
    def test_real_browser_loopback_request_binding(self) -> None:
        received_ids: list[str | None] = []
        body = b'{"generated_for":"internal-operations","settlement_queue":3}'

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                received_ids.append(self.headers.get("X-Ruby-Trial-Request-Id"))
                blocked = self.path.endswith("?blocked=1")
                payload = b'{"error":"blocked"}' if blocked else body
                self.send_response(403 if blocked else 200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_: object) -> None:
                return

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        issued: list[str] = []
        delivered: list[tuple[dict[str, object], bytes]] = []
        try:
            executor = ActionExecutor(
                f"http://127.0.0.1:{server.server_port}",
                private_request_observer=issued.append,
                private_response_observer=lambda result, content: delivered.append(
                    (result, content)
                ),
            )
            result = executor.execute_browser(
                {"session": "attacker", "path": "/api/v1/operations/export"}
            )
            blocked_result = executor.execute_browser(
                {
                    "session": "attacker",
                    "path": "/api/v1/operations/export?blocked=1",
                }
            )
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

        self.assertIn("internal-operations", result["body"])
        self.assertEqual(json.loads(result["body"]), json.loads(body))
        self.assertEqual(received_ids, issued)
        self.assertEqual(len(delivered), 2)
        self.assertEqual(delivered[0][0]["_trial_request_id"], issued[0])
        self.assertEqual(delivered[0][1], body)
        self.assertEqual(blocked_result["body"], '{"error":"blocked"}')
        self.assertEqual(delivered[1][0]["status"], 403)
        self.assertEqual(delivered[1][0]["_trial_request_id"], issued[1])
        self.assertNotIn("internal-operations", delivered[1][0]["response"])


if __name__ == "__main__":
    unittest.main()
