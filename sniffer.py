"""
Format sniffer: looks at the shape of a file's first few lines and decides
which extractor should handle it. This is deliberately shape-based, not
vendor-based -- it never asks "is this Fortinet," only "does this look
like JSON / CEF / coded syslog / CSV / generic key=value."
"""
import gzip
import json
import re


def open_maybe_compressed(filepath, mode="rt"):
    """Transparent gzip support: real ingestion pipelines routinely receive
    logs already rotated/shipped as .gz (syslog-ng, rsyslog omfile
    compression, S3 lifecycle exports, etc). Detecting by magic bytes
    rather than extension means a misnamed or extension-less file still
    works, which matters at Big-Data ingestion volume where files arrive
    from many different shippers."""
    with open(filepath, "rb") as probe:
        is_gzip = probe.read(2) == b"\x1f\x8b"
    if is_gzip:
        return gzip.open(filepath, mode, encoding="utf-8", errors="replace")
    return open(filepath, mode, encoding="utf-8", errors="replace")

CODED_SYSLOG_PATTERN = re.compile(r"%[A-Za-z0-9_]+-\d-\d+:")
KV_PATTERN = re.compile(r"\b\w+=(\"[^\"]*\"|\S+)")
LEEF_PATTERN = re.compile(r"LEEF:[\d.]+\|")
SYSLOG5424_PATTERN = re.compile(r"^<\d+>1\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\[|-)")


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

    if LEEF_PATTERN.search(line):
        return "leef"

    if "CEF:" in line:
        return "cef"

    if SYSLOG5424_PATTERN.match(line):
        return "syslog5424"

    if CODED_SYSLOG_PATTERN.search(line):
        return "coded_syslog"

    # CSV is only reliable to detect at file level (need the header row),
    # this per-line check is a weak fallback signal only.
    if line.count(",") >= 2 and "=" not in line and "%" not in line:
        return "csv_like"

    if len(KV_PATTERN.findall(line)) >= 3:
        # Ratio guard: genuine key=value syslog (Fortinet-style) is almost
        # entirely k=v tokens. Free-text logs that merely *contain* a
        # handful of k=v pairs (e.g. Linux auth failures embedding
        # "uid=0 euid=0 rhost=1.2.3.4" inside a prose sentence) shouldn't
        # be swept into this shape just because they clear the raw count.
        tokens = line.split()
        kv_ratio = len(KV_PATTERN.findall(line)) / max(len(tokens), 1)
        if kv_ratio >= 0.6:
            return "kv_syslog"

    return "unknown"


def sniff_file(filepath, sample_lines=5):
    """
    Reads a handful of lines and majority-votes the format.
    CSV gets special treatment: if the very first line looks like a header
    (comma-separated, no '=' signs) and following lines share its column
    count, we call it csv outright.
    """
    with open_maybe_compressed(filepath) as f:
        lines = []
        for _ in range(sample_lines + 1):
            line = f.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))

    if not lines:
        return "unknown"

    header = lines[0]
    # Guard against comma-heavy non-CSV shapes (e.g. coded-syslog message
    # bodies that happen to use comma-separated clauses) being mistaken
    # for a CSV header row purely because the column-count happens to
    # line up across sampled lines.
    looks_like_other_shape = (
        header.startswith("<")
        or LEEF_PATTERN.search(header)
        or "CEF:" in header
        or CODED_SYSLOG_PATTERN.search(header)
    )
    if "," in header and "=" not in header and not header.startswith("{") \
            and not looks_like_other_shape:
        header_cols = header.count(",")
        # Require at least 2 delimiters: a single stray comma (e.g.
        # "2016-09-28 04:30:30, Info    CBS   ...") lining up by
        # coincidence across sampled lines isn't a real CSV column set.
        if header_cols >= 2:
            body = lines[1:]
            if body and all(l.count(",") == header_cols for l in body if l.strip()):
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
