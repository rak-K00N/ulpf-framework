"""
Traceability layer (requirement d): every normalized event must be able
to point back to exactly where it came from -- which file, which line,
and when it was ingested -- without needing to re-scan the raw log to
find it. This is what makes the pipeline forensically/compliance sound:
an analyst (or an auditor) can always answer "show me the original event
this record came from."
"""
import hashlib
from datetime import datetime, timezone


def make_event_id(source_path, line_number, raw_line):
    """
    Deterministic, collision-resistant ID. Same input always produces the
    same ID -- re-running the pipeline on the same file doesn't create
    duplicate identities for the same event, which matters for replay /
    reprocessing scenarios.
    """
    basis = f"{source_path}:{line_number}:{raw_line}".encode("utf-8", "replace")
    return hashlib.sha256(basis).hexdigest()[:24]


def make_lineage(source_path, line_number, raw_line, source_name=None):
    return {
        "event_id": make_event_id(source_path, line_number, raw_line),
        "source_path": source_path,
        "source_name": source_name,
        "line_number": line_number,
        "ingested_at": datetime.now(timezone.utc).isoformat(),
    }
