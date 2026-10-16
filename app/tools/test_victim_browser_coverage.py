from __future__ import annotations

import unittest

from playwright.sync_api import sync_playwright

from victim_browser import VictimBrowser


class VictimBrowserCoverageTests(unittest.TestCase):
    def test_chromium_reports_execution_only_for_running_scripts(self) -> None:
        cases = (
            ("<html><head><title>static</title></head></html>", True, False),
            ("<html><head><title>static</title><script>document.title='changed'</script></head></html>", True, True),
            ("<html><head><meta http-equiv='Content-Security-Policy' content=\"script-src 'none'\"><script>document.title='blocked'</script></head></html>", True, False),
            ("<html><head><script>document.title='disabled'</script></head></html>", False, False),
            ("<html><head><title>static</title></head><body><img src=x onerror=\"document.title='handler'\"></body></html>", True, True),
            ("<html><head><style>@keyframes pulse{from{opacity:.1}to{opacity:1}}</style></head><body><div style='animation:pulse .01s' onanimationstart=\"document.title='animated'\">case</div></body></html>", True, True),
        )
        with sync_playwright() as driver:
            browser = driver.chromium.launch(headless=True, args=["--no-sandbox"])
            try:
                for html, enabled, expected in cases:
                    with self.subTest(html=html, javascript_enabled=enabled):
                        context = browser.new_context(java_script_enabled=enabled)
                        page = context.new_page()
                        inspector = context.new_cdp_session(page)
                        inspector.send("Profiler.enable")
                        inspector.send("Profiler.startPreciseCoverage", {"callCount": True, "detailed": True})
                        page.goto("data:text/html," + html, wait_until="load")
                        page.wait_for_timeout(100)
                        coverage = inspector.send("Profiler.takePreciseCoverage")["result"]
                        inspector.send("Profiler.stopPreciseCoverage")
                        self.assertEqual(VictimBrowser._executed_script(coverage), expected)
                        context.close()
            finally:
                browser.close()


if __name__ == "__main__":
    unittest.main()
