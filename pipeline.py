"""
The whole point of the project: process_file() takes any log file and
returns normalized events, without the caller ever needing to know or
specify what format it's in.

Also responsible for two things added for the ULPF requirements:
  - lineage stamping on every event (requirement d: traceability)
  - updating the source registry as new sources are seen
    (requirement e: plug-and-play onboarding)
"""
from parsers import cef, coded_syslog, csv_parser, json_flow, kv_syslog
from parsers.drain_fallback import DrainFallbackParser
import normalizer
from lineage import make_lineage
from sniffer import sniff_file, sniff_line
from registry import record_source_seen

_drain = DrainFallbackParser()


def process_file(filepath, source_name=None):
    """
    Yields (normalized_event, detected_format) for every line/row in
    filepath. This is the only function the outside world needs to call.
    """
    fmt = sniff_file(filepath)
    record_source_seen(source_name or filepath, filepath, fmt)

    if fmt == "csv":
        for i, row in enumerate(csv_parser.parse_file(filepath), start=1):
            raw_line = ",".join(row.values())
            lineage = make_lineage(filepath, i, raw_line, source_name)
            yield normalizer.normalize_csv(row, raw_line, lineage), fmt
        return

    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            lineage = make_lineage(filepath, i, line, source_name)
            yield process_line(line, fmt, lineage), fmt


def process_line(line, fmt_hint=None, lineage=None):
    """Processes a single line, given an already-known format hint."""
    fmt = fmt_hint or sniff_line(line)

    if fmt == "json":
        fields = json_flow.parse_line(line)
        if fields is not None:
            return normalizer.normalize_json_flow(fields, line, lineage)

    elif fmt == "cef":
        fields = cef.parse_line(line)
        if fields is not None:
            return normalizer.normalize_cef(fields, line, lineage)

    elif fmt == "coded_syslog":
        fields = coded_syslog.parse_line(line)
        if fields is not None:
            return normalizer.normalize_coded_syslog(fields, line, lineage)

    elif fmt == "kv_syslog":
        fields = kv_syslog.parse_line(line)
        if fields:
            return normalizer.normalize_kv_fortinet(fields, line, lineage)

    # nothing matched, or the shape-specific parser failed on this line
    # -> fall back to statistical template mining instead of dropping it
    drain_result = _drain.parse_line(line)
    return normalizer.normalize_drain(drain_result, line, lineage)
