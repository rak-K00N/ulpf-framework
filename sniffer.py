"""
Format sniffer: looks at the shape of a file's first few lines and decides
which extractor should handle it. This is deliberately shape-based, not
vendor-based -- it never asks "is this Fortinet," only "does this look
like JSON / CEF / coded syslog / CSV / generic key=value."
"""
import json
import re

CODED_SYSLOG_PATTERN = re.compile(r"%[A-Za-z0-9_]+-\d-\d+:")
KV_PATTERN = re.compile(r"\b\w+=(\"[^\"]*\"|\S+)")


def sniff_line(line):
    line = line.strip()
    if not line:
        return "empty"

    if line.startswith("{"):
        try:
            json.loads(line)
            return "json"
        except json.JSONDecodeError:
            pass

    if "CEF:" in line:
        return "cef"

    if CODED_SYSLOG_PATTERN.search(line):
        return "coded_syslog"

    # CSV is only reliable to detect at file level (need the header row),
    # this per-line check is a weak fallback signal only.
    if line.count(",") >= 2 and "=" not in line and "%" not in line:
        return "csv_like"

    if len(KV_PATTERN.findall(line)) >= 3:
        return "kv_syslog"

    return "unknown"


def sniff_file(filepath, sample_lines=5):
    """
    Reads a handful of lines and majority-votes the format.
    CSV gets special treatment: if the very first line looks like a header
    (comma-separated, no '=' signs) and following lines share its column
    count, we call it csv outright.
    """
    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
        lines = []
        for _ in range(sample_lines + 1):
            line = f.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))

    if not lines:
        return "unknown"

    header = lines[0]
    header_fields = [field.strip() for field in header.split(",")]
    header_looks_named = (
        len(header_fields) >= 2
        and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ -]*", field)
                for field in header_fields)
    )
    if header_looks_named and "=" not in header and not header.startswith("{"):
        header_cols = len(header_fields)
        body = lines[1:]
        if body and all(len(l.split(",")) == header_cols for l in body if l.strip()):
            return "csv"

    votes = {}
    for line in lines:
        fmt = sniff_line(line)
        if fmt in ("empty", "csv_like"):
            continue
        votes[fmt] = votes.get(fmt, 0) + 1

    if not votes:
        return "unknown"
    return max(votes, key=votes.get)
