from __future__ import annotations

import json
import uuid

from autonomous_cve_target_adapters_v3 import prepare_jenkins_target


def check_release(release: str) -> dict[str, object]:
    prepared = prepare_jenkins_target(uuid.uuid4().hex, 30, release_name=release)
    try:
        executor = prepared.executor
        effects: list[str] = []
        executor._record_effect_once = lambda: effects.append("protected-file-disclosed")
        normal = executor.execute_jenkins_cli(
            {
                "kind": "jenkins_cli",
                "session": "attacker",
                "command": "help",
                "arguments": ["version"],
            }
        )
        normal_effects = len(effects)
        attack = executor.execute_jenkins_cli(
            {
                "kind": "jenkins_cli",
                "session": "attacker",
                "command": "help",
                "arguments": ["@/tmp/ruby-cve-marker.txt"],
            }
        )
        return {
            "release": release,
            "normal_effects": normal_effects,
            "attack_effects": len(effects) - normal_effects,
            "normal_returncode": normal["returncode"],
            "attack_returncode": attack["returncode"],
        }
    finally:
        prepared.cleanup()


if __name__ == "__main__":
    for name in ("vulnerable", "fixed"):
        print(json.dumps(check_release(name)), flush=True)
