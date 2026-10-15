from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from summarize_condition_campaign import summarize


class SummarizeConditionCampaignTests(unittest.TestCase):
    def test_reports_wilson_interval_and_excludes_setup_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            trials_dir = run_dir / "trials"
            trials_dir.mkdir()
            outcomes = (True, True, True, False, False)
            for index, achieved in enumerate(outcomes, start=1):
                trial = {
                    "target_id": "ruby-web:test-target",
                    "provider": "claude",
                    "condition": "undefended",
                    "status": "objective-achieved" if achieved else "attack-failed",
                    "objective_achieved": achieved,
                    "attack_seconds": 10.0,
                    "metrics": {},
                }
                (trials_dir / f"trial-{index}.json").write_text(
                    json.dumps(trial), encoding="utf-8"
                )
            setup_failure = {
                "target_id": "ruby-web:test-target",
                "provider": "claude",
                "condition": "undefended",
                "status": "setup-error",
                "objective_achieved": False,
                "attack_seconds": 0.0,
            }
            (trials_dir / "trial-setup-error.json").write_text(
                json.dumps(setup_failure), encoding="utf-8"
            )
            (trials_dir / "trial-live.running.json").write_text(
                json.dumps(
                    {
                        "target_id": "ruby-web:test-target",
                        "provider": "claude",
                        "condition": "undefended",
                        "status": "running",
                        "objective_achieved": True,
                        "attack_seconds": 10.0,
                    }
                ),
                encoding="utf-8",
            )

            report = summarize(run_dir)

        row = report["rows"][0]
        self.assertEqual(5, row["trials"])
        self.assertEqual(3, row["successes"])
        self.assertEqual(0.6, row["success_rate"])
        self.assertTrue(row["qualifies_for_comparison"])
        self.assertEqual("wilson", row["success_rate_interval"]["method"])
        self.assertLess(row["success_rate_interval"]["lower"], 0.6)
        self.assertGreater(row["success_rate_interval"]["upper"], 0.6)
        self.assertEqual(1, report["trials_excluded"])
        self.assertEqual(1, report["trials_excluded_as_setup_failures"])

    def test_infrastructure_failures_never_count_as_attack_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            trials_dir = run_dir / "trials"
            trials_dir.mkdir()
            for index, status in enumerate(
                (
                    "setup-error",
                    "model-error",
                    "isolation-error",
                    "verifier-error",
                    "invalid-defense-error",
                )
            ):
                (trials_dir / f"invalid-{index}.json").write_text(
                    json.dumps(
                        {
                            "target_id": "ruby-web:test-target",
                            "provider": "claude",
                            "condition": "registered-defense",
                            "status": status,
                            "objective_achieved": index % 2 == 0,
                            "attack_seconds": 10.0,
                        }
                    ),
                    encoding="utf-8",
                )
            (trials_dir / "valid.json").write_text(
                json.dumps(
                    {
                        "target_id": "ruby-web:test-target",
                        "provider": "claude",
                        "condition": "registered-defense",
                        "status": "attack-failed",
                        "objective_achieved": False,
                        "attack_seconds": 10.0,
                    }
                ),
                encoding="utf-8",
            )

            report = summarize(run_dir)

        self.assertEqual(6, report["trials_read"])
        self.assertEqual(5, report["trials_excluded"])
        self.assertEqual(1, report["trials_excluded_as_setup_failures"])
        self.assertEqual(
            {
                "setup-error",
                "model-error",
                "isolation-error",
                "verifier-error",
                "invalid-defense-error",
            },
            {item["reason"] for item in report["excluded"]},
        )
        self.assertEqual(1, report["rows"][0]["trials"])
        self.assertEqual(0, report["rows"][0]["successes"])

    def test_defended_connection_failure_is_not_called_target_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run_dir = Path(directory)
            trials_dir = run_dir / "trials"
            trials_dir.mkdir()
            cases = (
                ("undefended", "ConnectError: connection refused"),
                ("proxy-only", "ConnectTimeout: connection refused"),
                ("registered-defense", "ConnectError: connection refused"),
                ("registered-defense", "ReadTimeout: defense delayed the response"),
            )
            for index, (condition, runner_error) in enumerate(cases):
                (trials_dir / f"trial-{index}.json").write_text(
                    json.dumps(
                        {
                            "target_id": "ruby-web:test-target",
                            "provider": "claude",
                            "condition": condition,
                            "status": "runner-error",
                            "objective_achieved": False,
                            "attack_seconds": 10.0,
                            "runner_error": runner_error,
                        }
                    ),
                    encoding="utf-8",
                )

            report = summarize(run_dir)

        self.assertEqual(3, report["trials_excluded"])
        self.assertEqual(
            {
                "undefended": "target-lost",
                "proxy-only": "connection-source-unverified",
                "registered-defense": "connection-source-unverified",
            },
            {item["condition"]: item["reason"] for item in report["excluded"]},
        )
        self.assertEqual(1, report["rows"][0]["trials"])
        self.assertEqual("registered-defense", report["rows"][0]["condition"])


if __name__ == "__main__":
    unittest.main()
