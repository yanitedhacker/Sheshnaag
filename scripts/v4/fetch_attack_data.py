#!/usr/bin/env python3
"""Fetch the latest MITRE ATT&CK Enterprise STIX bundle.

Pulls the official ``enterprise-attack.json`` bundle from
``https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json``
and rewrites ``app/data/attack/enterprise-attack.json`` with a curated
subset (technique id, name, tactic, parent, description) so we don't carry
~50 MB of STIX artefacts in the repo.

Idempotent. Safe to wire into CI as a weekly refresh.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def _kill_chain_to_tactic(kill_chain_phases: list[dict]) -> str:
    if not kill_chain_phases:
        return "Unknown"
    name = kill_chain_phases[0].get("phase_name") or ""
    return " ".join(part.capitalize() for part in name.replace("_", "-").split("-"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument(
        "--output",
        default=str(Path(__file__).resolve().parents[2] / "app" / "data" / "attack" / "enterprise-attack.json"),
    )
    args = parser.parse_args(argv)

    print(f"[fetch_attack_data] downloading {args.url}", file=sys.stderr)
    with urllib.request.urlopen(args.url, timeout=60) as response:
        bundle = json.load(response)

    techniques: list[dict] = []
    by_id: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        external_id = next(
            (
                ref.get("external_id")
                for ref in obj.get("external_references") or []
                if ref.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not external_id:
            continue
        record = {
            "technique_id": external_id,
            "name": obj.get("name", ""),
            "tactic": _kill_chain_to_tactic(obj.get("kill_chain_phases") or []),
            "description": (obj.get("description") or "").splitlines()[0][:480],
        }
        if obj.get("x_mitre_is_subtechnique") and "." in external_id:
            record["parent"] = external_id.split(".")[0]
        by_id[external_id] = record

    # Resolve subtechniques onto their parents.
    for record in by_id.values():
        if "parent" in record:
            parent = by_id.get(record["parent"])
            if parent is not None:
                parent.setdefault("subtechniques", []).append(record["technique_id"])

    techniques = sorted(by_id.values(), key=lambda r: r["technique_id"])
    output = {
        "version": bundle.get("x_mitre_version", "unknown"),
        "schema_version": "v4.1",
        "source": args.url,
        "techniques": techniques,
    }
    Path(args.output).write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[fetch_attack_data] wrote {len(techniques)} techniques to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
