"""Loader for the maintainable MITRE ATT&CK mapping file (mappings.json)."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_PATH = Path(__file__).with_name("mappings.json")


@lru_cache
def load_mappings() -> dict[str, Any]:
    with _PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def build_mapping(key: str, observed: str, relation: str | None = None) -> dict[str, Any]:
    """Create a mapping entry for a finding. `observed` states what was actually seen in the logs."""
    data = load_mappings()
    m = data["mappings"][key]  # KeyError on typos is intentional: mappings must exist in the data file
    rel = relation or m["default_relation"]
    return {
        "key": key,
        "technique_id": m["technique_id"],
        "technique_name": m["name"],
        "tactics": m["tactics"],
        "url": m["url"],
        "relation": rel,
        "relation_meaning": data["relations"][rel],
        "observed_behavior": observed,
        "rationale": m["rationale"],
    }


def merge_mappings(lists: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for lst in lists:
        for m in lst:
            seen.setdefault(m["technique_id"], m)
    return list(seen.values())
