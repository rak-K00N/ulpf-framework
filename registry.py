"""
Requirement e: plug-and-play onboarding of new log sources.

The registry is the record of "what sources does this deployment know
about." For the four self-describing shapes (json/csv/kv/cef), onboarding
a brand-new vendor genuinely requires zero new code -- the moment a file
is processed, it's auto-registered here. For coded-syslog and unknown
shapes, this file also tracks whether a source is still running through
the (slower, lower-confidence) fallback path or has a proper codebook.

This is deliberately a flat JSON file, not a database -- easy to inspect,
easy to ship inside a container, easy to diff in version control.
"""
import json
import os
from datetime import datetime, timezone

_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "registry_state.json")


def _load():
    if not os.path.exists(_REGISTRY_PATH):
        return {}
    with open(_REGISTRY_PATH, "r") as f:
        return json.load(f)


def _save(state):
    with open(_REGISTRY_PATH, "w") as f:
        json.dump(state, f, indent=2)


def record_source_seen(source_name, filepath, detected_format):
    """Called automatically by the pipeline every time a file is processed."""
    state = _load()
    now = datetime.now(timezone.utc).isoformat()

    entry = state.get(source_name, {
        "source_name": source_name,
        "first_seen": now,
        "detected_format": detected_format,
        "onboarding_status": _onboarding_status(detected_format),
        "files_processed": 0,
    })
    entry["last_seen"] = now
    entry["detected_format"] = detected_format
    entry["onboarding_status"] = _onboarding_status(detected_format)
    entry["files_processed"] = entry.get("files_processed", 0) + 1
    entry["last_file"] = filepath

    state[source_name] = entry
    _save(state)
    return entry


def _onboarding_status(detected_format):
    if detected_format in ("json", "csv", "kv_syslog", "cef"):
        return "auto (zero-code, self-describing shape)"
    if detected_format == "coded_syslog":
        return "codebook-driven (JSON config only)"
    return "fallback (statistical, needs review before trusting fully)"


def list_sources():
    return list(_load().values())


def print_registry():
    sources = list_sources()
    if not sources:
        print("No sources onboarded yet.")
        return
    print(f"{'Source':<28} {'Format':<14} {'Status':<45} {'Files'}")
    print("-" * 100)
    for s in sources:
        print(f"{s['source_name']:<28} {s['detected_format']:<14} "
              f"{s['onboarding_status']:<45} {s['files_processed']}")
