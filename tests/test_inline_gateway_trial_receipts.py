from __future__ import annotations

import unittest

from app.tools.inline_defense_gateway_v2 import _preserve_trial_request_id


class InlineGatewayTrialReceiptTests(unittest.TestCase):
    def test_rewrite_keeps_the_original_trial_id(self) -> None:
        original = [("X-Ruby-Trial-Request-Id", "a" * 32)]
        rewritten = [
            ("Accept", "application/json"),
            ("x-ruby-trial-request-id", "b" * 32),
        ]
        self.assertEqual(
            [
                ("Accept", "application/json"),
                ("X-Ruby-Trial-Request-Id", "a" * 32),
            ],
            _preserve_trial_request_id(original, rewritten),
        )

    def test_defense_cannot_create_a_trial_id_from_an_untagged_request(self) -> None:
        self.assertEqual(
            [],
            _preserve_trial_request_id(
                [],
                [("X-Ruby-Trial-Request-Id", "b" * 32)],
            ),
        )


if __name__ == "__main__":
    unittest.main()
