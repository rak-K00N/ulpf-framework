"""
Every parser above returns fields with different names. This is the layer
that makes it "universal" from the consumer's point of view: no matter
which of the five(+) source formats an event came from, it leaves here
looking identical.
"""
from datetime import datetime, timezone

from schema import empty_event, normalize_action, normalize_protocol, to_int, guess_action_from_text
from parsers import generic_profiler, kv_syslog


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


def normalize_leef(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "leef", lineage)
    event["timestamp"] = fields.get("devTime") or fields.get("syslog_prefix")
    event["vendor"] = (fields.get("vendor") or "").lower() or "unknown"
    event["event_type"] = fields.get("cat")
    event["action"] = normalize_action(fields.get("act") or fields.get("event_id"))
    event["src_ip"] = fields.get("src") or fields.get("srcIP")
    event["src_port"] = to_int(fields.get("srcPort"))
    event["dst_ip"] = fields.get("dst") or fields.get("dstIP")
    event["dst_port"] = to_int(fields.get("dstPort"))
    event["protocol"] = normalize_protocol(fields.get("proto"))
    event["bytes_sent"] = to_int(fields.get("bytesOut") or fields.get("sentBytes"))
    event["bytes_received"] = to_int(fields.get("bytesIn") or fields.get("rcvdBytes"))
    event["user"] = fields.get("usrName") or fields.get("suser")
    event["message"] = fields.get("msg") or fields.get("cat")
    event["confidence"] = 0.95
    return event


def normalize_syslog5424(fields, raw_line, lineage=None):
    event = empty_event(raw_line, "syslog5424", lineage)
    event["timestamp"] = fields.get("timestamp")
    event["vendor"] = fields.get("appname", "unknown")
    event["event_type"] = "traffic" if fields.get("srcIP") else "other"
    event["action"] = normalize_action(fields.get("action"))
    event["src_ip"] = fields.get("srcIP")
    event["src_port"] = to_int(fields.get("srcPort"))
    event["dst_ip"] = fields.get("dstIP")
    event["dst_port"] = to_int(fields.get("dstPort"))
    event["protocol"] = normalize_protocol(fields.get("proto"))
    event["bytes_sent"] = to_int(fields.get("bytesSent"))
    event["bytes_received"] = to_int(fields.get("bytesRecv"))
    event["user"] = fields.get("user")
    event["message"] = fields.get("message")
    # structured-data-bearing lines are as reliable as CEF/LEEF; bare
    # RFC5424 lines with no SD-ELEMENT are still well-formed but carry
    # nothing beyond free text, so confidence reflects that split.
    event["confidence"] = 0.95 if fields.get("has_structured_data") else 0.5
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


def normalize_drain(drain_result, raw_line, lineage=None):
    """
    Normalizes whatever came out of the Drain fallback path (flow-chart
    boxes 6+7 -> 8). Three independent, purely shape-based signals are
    combined here, none of them vendor-specific:

      1. generic_profiler: line-level shapes (timestamp/severity/host/
         process) recognized directly on the untouched raw line.
      2. kv_syslog: opportunistic key=value fragment harvesting -- many
         "unknown" formats still embed a few k=v pairs inside otherwise
         free-text lines (e.g. Linux auth failures: "uid=0 rhost=1.2.3.4").
      3. Drain's own tagged variable tokens, used as a last resort for
         anything the first two passes didn't already claim.

    Confidence is built up from how much of this actually fired, rather
    than a single flat "fallback" number -- a log that yielded a
    timestamp, a severity, a host and an IP is meaningfully more useful
    than one where nothing beyond the raw template was recoverable.
    """
    event = empty_event(raw_line, "unknown", lineage)
    event["message"] = drain_result["template"]

    profile = generic_profiler.profile_line(raw_line)
    kv_fields = kv_syslog.parse_line(raw_line)

    confidence = 0.30

    if profile["timestamp"]:
        event["timestamp"] = profile["timestamp"]
        confidence += 0.10
    else:
        # Second line of defense: none of generic_profiler's ~10 known
        # timestamp shapes matched (a genuinely new format may use one
        # nobody's seen yet), but Drain may still have isolated a
        # date-shaped or time-shaped token as a *variable* purely from
        # its position varying line-to-line. Cheaper than adding a new
        # regex, and catches e.g. a bare "14:22:01" with no date part.
        date_tok = next((v["value"] for v in drain_result["variables"]
                          if v["guessed_type"] == "date"), None)
        time_tok = next((v["value"] for v in drain_result["variables"]
                          if v["guessed_type"] == "time"), None)
        fallback_ts = " ".join(t for t in (date_tok, time_tok) if t)
        if fallback_ts:
            event["timestamp"] = fallback_ts
            confidence += 0.05
    if profile["severity"]:
        event["severity"] = profile["severity"]
        confidence += 0.05
    if profile["host"]:
        event["host"] = profile["host"]
        confidence += 0.05
    if profile["process"]:
        event["process"] = profile["process"]
        event["pid"] = profile["pid"]
        confidence += 0.05

    # opportunistic k=v harvesting: common field-name aliases across the
    # sampled corpora (auth logs, cloud logs, appliance logs, ...).
    # Trailing punctuation ("uid=10037," picked up mid-sentence) gets
    # trimmed since kv_syslog's \S+ value matcher has no clause boundary
    # to stop at in free prose the way it does in a real k=v log line.
    def _clean(v):
        return v.rstrip(",;:.!?)") if v else v

    user_val = (kv_fields.get("user") or kv_fields.get("uid")
                or kv_fields.get("ruser") or kv_fields.get("username"))
    if user_val:
        event["user"] = _clean(user_val)
        confidence += 0.05

    ip_from_kv = (kv_fields.get("rhost") or kv_fields.get("host")
                  or kv_fields.get("ip") or kv_fields.get("src")
                  or kv_fields.get("srcip"))
    dst_from_kv = kv_fields.get("dst") or kv_fields.get("dstip")
    ip_from_kv = _clean(ip_from_kv)
    dst_from_kv = _clean(dst_from_kv)

    ip_vars = [v["value"] for v in drain_result["variables"] if v["guessed_type"] == "ip"]
    flow_vars = [v for v in drain_result["variables"] if v["guessed_type"] == "ip_port_flow"]
    ip_port_vars = [v for v in drain_result["variables"] if v["guessed_type"] == "ip_port"]

    src_ip = src_port = dst_ip = dst_port = None
    if flow_vars:
        # "SRC:PORT->DST:PORT" in one token -- highest-confidence source,
        # common router/firewall connection-log notation (MikroTik,
        # iptables, envoy/HAProxy access logs, ...).
        f = flow_vars[0]
        src_ip, src_port = f["src_ip"], f["src_port"]
        dst_ip, dst_port = f["dst_ip"], f["dst_port"]
    elif ip_port_vars:
        # Two separate "IP:PORT" tokens, positionally first = source.
        src_ip, src_port = ip_port_vars[0]["ip"], ip_port_vars[0]["port"]
        if len(ip_port_vars) >= 2:
            dst_ip, dst_port = ip_port_vars[1]["ip"], ip_port_vars[1]["port"]

    src_ip = ip_from_kv or src_ip or (ip_vars[0] if ip_vars else None)
    dst_ip = dst_from_kv or dst_ip or (ip_vars[1] if len(ip_vars) >= 2 else
                                        (ip_vars[0] if ip_vars and ip_from_kv else None))
    if src_ip:
        event["src_ip"] = src_ip
        event["src_port"] = to_int(src_port)
        confidence += 0.10
    if dst_ip and dst_ip != src_ip:
        event["dst_ip"] = dst_ip
        event["dst_port"] = to_int(dst_port)

    # Fallback for plain (non-IP-attached) port-shaped numbers, only when
    # we didn't already get a port from a more specific ip_port/flow token.
    port_vars = [v["value"] for v in drain_result["variables"]
                 if v["guessed_type"] == "port_or_number"]
    if event["src_ip"] and event["src_port"] is None and len(port_vars) >= 1:
        event["src_port"] = to_int(port_vars[0])
    if event["dst_ip"] and event["dst_port"] is None and len(port_vars) >= 2:
        event["dst_port"] = to_int(port_vars[1])

    # severity carries real signal even without a recognized action verb;
    # otherwise fall back to scanning the free-text template for one.
    event["action"] = guess_action_from_text(drain_result["template"])
    event["event_type"] = "traffic" if event["src_ip"] else "unclassified"

    event["confidence"] = round(min(confidence, 0.75), 2)
    return event
