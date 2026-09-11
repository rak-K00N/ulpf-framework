"""
Common normalized schema every parser output gets mapped into.
Loosely inspired by OCSF / ECS network-activity conventions, trimmed down
for this prototype. This is the "universal" contract: every downstream
consumer (dashboard, SIEM, whatever) only ever needs to know this shape,
never the original vendor format.
"""
import re

NORMALIZED_FIELDS = [
    "event_id",         # stable hash: uniquely identifies this event forever
    "timestamp",
    "vendor",
    "source_format",   # json | csv | kv_syslog | cef | leef | syslog5424 |
                        # coded_syslog | unknown
    "event_type",      # traffic | auth | connection | flow | admin | other
    "action",          # allow | deny | auth | other
    "severity",        # debug | info | warning | error | critical | unknown
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "packets",
    "user",
    "host",            # device/machine name the event originated on, when known
    "process",         # process/service name, when known (generic fallback path)
    "pid",
    "message",
    "confidence",       # 0.0-1.0, how sure the parser is about this event
    "lineage",          # dict: exactly where this came from, for forensics/audit
    "raw",              # original untouched log line, always kept
]

PROTO_NUM_TO_NAME = {"1": "icmp", "6": "tcp", "17": "udp"}

ACTION_MAP = {
    "allow": "allow", "accept": "allow", "permit": "allow", "built": "allow",
    "successful": "allow", "success": "allow",
    "deny": "deny", "reject": "deny", "block": "deny", "blocked": "deny",
    "rejected": "deny", "drop": "deny", "dropped": "deny",
    "login": "auth", "authentication": "auth",
    "teardown": "other",
}


def normalize_action(raw_action):
    if raw_action is None:
        return "other"
    key = str(raw_action).strip().lower()
    return ACTION_MAP.get(key, "other")


def guess_action_from_text(text):
    """Looser version of normalize_action for free-text fallback lines:
    scans for any ACTION_MAP keyword appearing as a whole word anywhere
    in the text, rather than requiring the whole field to equal one
    exactly. Used only by the unknown-format path, where there's no
    single well-defined 'action' field to read from -- just prose that
    may or may not mention one of these words."""
    if not text:
        return "other"
    lowered = text.lower()
    for keyword, action in ACTION_MAP.items():
        if re.search(rf"\b{re.escape(keyword)}\b", lowered):
            return action
    return "other"


def normalize_protocol(raw_proto):
    if raw_proto is None:
        return None
    val = str(raw_proto).strip().lower()
    if val in PROTO_NUM_TO_NAME:
        return PROTO_NUM_TO_NAME[val]
    if val in ("tcp", "udp", "icmp"):
        return val
    return val


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def empty_event(raw_line, source_format, lineage=None):
    """A skeleton event so every field always exists, even if unfilled."""
    event = {f: None for f in NORMALIZED_FIELDS}
    event["raw"] = raw_line
    event["source_format"] = source_format
    event["confidence"] = 0.0
    event["lineage"] = lineage
    if lineage:
        event["event_id"] = lineage.get("event_id")
    return event
