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

try:
    import fcntl
    _HAVE_FCNTL = True
except ImportError:
    # Windows has no fcntl. Registry updates are only ever called from
    # single-process pipeline runs there, so this is a documented gap,
    # not a silent one -- see the comment on record_source_seen below.
    _HAVE_FCNTL = False

_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "registry_state.json")
_LOCK_PATH = _REGISTRY_PATH + ".lock"


def _load():
    if not os.path.exists(_REGISTRY_PATH):
        return {}
    with open(_REGISTRY_PATH, "r") as f:
        return json.load(f)


def _save(state):
    with open(_REGISTRY_PATH, "w") as f:
        json.dump(state, f, indent=2)


def record_source_seen(source_name, filepath, detected_format):
    """
    Called automatically by the pipeline every time a file is processed.

    This is a read-modify-write on one shared JSON file. Fine as long as
    only one process ever calls it -- which was true until
    run_demo_parallel.py started running one worker process per source
    file. Concurrent load()+save() from two workers can interleave and
    corrupt registry_state.json (each worker's save() overwrites the
    other's, or a save() lands mid-read for another). An flock() around
    the whole read-modify-write serializes registry updates across
    processes -- worker parsing stays fully parallel (that's the
    expensive part); only this small, infrequent bookkeeping write is
    now single-file-at-a-time, which costs nothing measurable.
    """
    if not _HAVE_FCNTL:
        return _record_source_seen_unlocked(source_name, filepath, detected_format)

    lock_f = open(_LOCK_PATH, "w")
    try:
        fcntl.flock(lock_f, fcntl.LOCK_EX)
        return _record_source_seen_unlocked(source_name, filepath, detected_format)
    finally:
        fcntl.flock(lock_f, fcntl.LOCK_UN)
        lock_f.close()


def _record_source_seen_unlocked(source_name, filepath, detected_format):
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
    if detected_format in ("json", "csv", "kv_syslog", "cef", "leef", "syslog5424"):
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
