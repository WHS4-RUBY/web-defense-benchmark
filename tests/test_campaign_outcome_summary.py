from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app" / "tools"))

from run_autonomous_campaign_v3 import _campaign_outcome_counts  # noqa: E402


class CampaignOutcomeSummaryTests(unittest.TestCase):
    def test_raw_count_is_preserved_but_invalid_trials_do_not_count_as_valid(self) -> None:
        reports = [
            {
                "condition": "undefended",
                "status": "objective-achieved",
                "objective_achieved": True,
                "attack_seconds": 10.0,
            },
            {
                "condition": "registered-defense",
                "status": "invalid-defense-error",
                "objective_achieved": True,
                "attack_seconds": 10.0,
            },
            {
                "condition": "registered-defense",
                "status": "runner-error",
                "objective_achieved": True,
                "attack_seconds": 10.0,
                "runner_error": "ConnectError: connection refused",
            },
            {
                "condition": "registered-defense",
                "status": "runner-error",
                "objective_achieved": False,
                "attack_seconds": 10.0,
                "runner_error": "ReadTimeout: defense delayed the response",
            },
            {
                "condition": "undefended",
                "status": "runner-error",
                "objective_achieved": False,
                "attack_seconds": 10.0,
                "runner_error": "ConnectError: target unavailable",
            },
            {
                "condition": "undefended",
                "status": "model-error",
                "objective_achieved": True,
                "attack_seconds": 10.0,
            },
        ]

        counts = _campaign_outcome_counts(reports)

        self.assertEqual(4, counts["objective_successes"])
        self.assertEqual(2, counts["valid_trials"])
        self.assertEqual(1, counts["valid_objective_successes"])
        self.assertEqual(
            {
                "connection-source-unverified": 1,
                "invalid-defense-error": 1,
                "model-error": 1,
                "target-lost": 1,
            },
            counts["excluded_trial_counts"],
        )


if __name__ == "__main__":
    unittest.main()
