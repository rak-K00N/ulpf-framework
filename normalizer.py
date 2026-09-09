"""
Every parser above returns fields with different names. This is the layer
that makes it "universal" from the consumer's point of view: no matter
which of the five(+) source formats an event came from, it leaves here
looking identical.
"""
from datetime import datetime, timezone
import re

from schema import empty_event, normalize_action, normalize_protocol, to_int


def epoch_to_iso(epoch_value):
    """Every event's timestamp field must be the same type (ISO string)
    regardless of source -- some formats give us epoch seconds instead."""
    try:
        return datetime.fromtimestamp(int(epoch_value), tz=timezone.utc).isoformat()
    except (TypeError, ValueError):
        return None


def normalize_kv_fortinet(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "kv_syslog", lineage)
    event["timestamp"] = f"{fields.get('date', '')} {fields.get('time', '')}".strip()
    event["vendor"] = "fortinet"
    event["event_type"] = fields.get("type")
    event["action"] = normalize_action(fields.get("action"))
    event["src_ip"] = fields.get("srcip")
    event["src_port"] = to_int(fields.get("srcport"))
    event["dst_ip"] = fields.get("dstip")
    event["dst_port"] = to_int(fields.get("dstport"))
    event["protocol"] = normalize_protocol(fields.get("proto"))
    event["bytes_sent"] = to_int(fields.get("sentbyte"))
    event["bytes_received"] = to_int(fields.get("rcvdbyte"))
    event["user"] = fields.get("user")
    event["message"] = fields.get("msg")
    event["confidence"] = 0.95
    return event


def normalize_cef(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "cef", lineage)
    event["timestamp"] = fields.get("syslog_prefix")
    event["vendor"] = fields.get("vendor", "").lower() or "unknown"
    event["event_type"] = fields.get("cat")
    event["action"] = normalize_action(fields.get("act"))
    event["src_ip"] = fields.get("src")
    event["src_port"] = to_int(fields.get("spt"))
    event["dst_ip"] = fields.get("dst")
    event["dst_port"] = to_int(fields.get("dpt"))
    event["protocol"] = normalize_protocol(fields.get("proto"))
    event["bytes_sent"] = to_int(fields.get("out"))
    event["bytes_received"] = to_int(fields.get("in"))
    event["user"] = fields.get("duser")
    event["message"] = fields.get("msg")
    event["confidence"] = 0.95
    return event


def normalize_json_flow(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "json", lineage)
    event["timestamp"] = epoch_to_iso(fields.get("start"))
    event["vendor"] = "cloud"
    event["event_type"] = "flow"
    event["action"] = normalize_action(fields.get("action"))
    event["src_ip"] = fields.get("srcaddr")
    event["src_port"] = to_int(fields.get("srcport"))
    event["dst_ip"] = fields.get("dstaddr")
    event["dst_port"] = to_int(fields.get("dstport"))
    event["protocol"] = normalize_protocol(fields.get("protocol"))
    event["bytes_sent"] = to_int(fields.get("bytes"))
    event["packets"] = to_int(fields.get("packets"))
    event["confidence"] = 0.98
    return event


def normalize_csv(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "csv", lineage)
    event["timestamp"] = fields.get("timestamp")
    event["vendor"] = "generic"
    event["event_type"] = "traffic"
    event["action"] = normalize_action(fields.get("action"))
    event["src_ip"] = fields.get("source_ip")
    event["src_port"] = to_int(fields.get("source_port"))
    event["dst_ip"] = fields.get("destination_ip")
    event["dst_port"] = to_int(fields.get("destination_port"))
    event["protocol"] = normalize_protocol(fields.get("protocol"))
    event["bytes_sent"] = to_int(fields.get("bytes_sent"))
    event["bytes_received"] = to_int(fields.get("bytes_received"))
    event["packets"] = to_int(fields.get("packets"))
    event["confidence"] = 0.98
    return event


def normalize_coded_syslog(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "coded_syslog", lineage)
    event["timestamp"] = fields.get("timestamp")
    event["vendor"] = fields.get("vendor", "unknown")
    event["event_type"] = fields.get("event_type")
    event["action"] = fields.get("action", "other")
    event["src_ip"] = fields.get("src_ip")
    event["src_port"] = to_int(fields.get("src_port"))
    event["dst_ip"] = fields.get("dst_ip")
    event["dst_port"] = to_int(fields.get("dst_port"))
    event["protocol"] = normalize_protocol(fields.get("protocol"))
    event["bytes_sent"] = to_int(fields.get("bytes"))
    event["user"] = fields.get("user")
    event["message"] = fields.get("description")

    if not fields.get("matched_code"):
        event["confidence"] = 0.3   # header parsed, code unknown
    elif not fields.get("body_matched"):
        event["confidence"] = 0.5   # code known, body template drifted
    else:
        event["confidence"] = 0.9   # fully matched

    return event


def _drain_confidence(drain_result):
    """Score fallback events from evidence available without a schema."""
    template = drain_result.get("template", "")
    variables = drain_result.get("variables", [])
    cluster_size = drain_result.get("cluster_size") or 0
    recognized_types = [v["guessed_type"] for v in variables]

    score = 0.2
    if cluster_size >= 2:
        score += 0.15
    if cluster_size >= 10:
        score += 0.1
    score += min(recognized_types.count("ip"), 2) * 0.1
    score += min(recognized_types.count("port_or_number"), 2) * 0.05
    if re.search(r"\b\d{4}-\d{2}-\d{2}\b", template):
        score += 0.05
    if re.search(r"\b(allow|permit|accept|deny|reject|drop|block|blocked)\b",
                 template, re.IGNORECASE):
        score += 0.1
    if re.search(r"\b(tcp|udp|icmp)\b", template, re.IGNORECASE):
        score += 0.05
    return round(min(score, 0.85), 2)


def normalize_drain(drain_result, raw_line, lineage=None):
    event = empty_event(raw_line, "unknown", lineage)
    event["event_type"] = "unclassified"
    event["action"] = "other"
    event["message"] = drain_result["template"]

    # cheap heuristic promotion: if exactly one ip-shaped and one
    # port-shaped variable show up early, guess at src/dst without
    # pretending to real confidence
    ip_vars = [v["value"] for v in drain_result["variables"] if v["guessed_type"] == "ip"]
    if len(ip_vars) >= 1:
        event["src_ip"] = ip_vars[0]
    if len(ip_vars) >= 2:
        event["dst_ip"] = ip_vars[1]

    event["confidence"] = _drain_confidence(drain_result)
    return event
