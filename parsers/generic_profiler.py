"""
Heuristic Field-Type Tagging (flow-chart box 7).

This is deliberately NOT a per-vendor parser. It never knows what
"Android", "BGL", or "OpenSSH" is. It only recognizes a handful of
well-known, widely-published SHAPES that show up near the front of
almost any line-oriented log, regardless of source:

  - a timestamp, in one of a dozen common published styles
  - a log level / severity word
  - an RFC 3164-style hostname sitting right after a BSD-style timestamp
  - a process/service name and PID in "name[1234]:" or "name(sub)[1234]:"
    form (the standard syslog TAG field)

Anything not matched by these shape rules is left alone and falls through
to Drain's statistical template mining untouched. Adding a new log
source that already uses one of these common shapes requires adding
nothing here -- that is the point.
"""
import re

# Ordered by specificity -- first match wins so a more precise shape
# (e.g. one that also captures milliseconds) isn't shadowed by a looser
# one that matches a prefix of it.
_TIMESTAMP_PATTERNS = [
    # 2015-10-18 18:01:47,978  /  2016-09-28 04:30:30,  (Hadoop, Windows)
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}[.,]\d+",
    # 2005-06-03-15.42.50.675872  (BGL/Thunderbird full precision stamp)
    r"\d{4}-\d{2}-\d{2}-\d{2}\.\d{2}\.\d{2}\.\d+",
    # 2005.06.03  (BGL date-only field)
    r"\d{4}\.\d{2}\.\d{2}",
    # 2015-10-18 18:01:47  (ISO, no fractional seconds)
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}",
    # 20171223-22:15:29:606  (HealthApp; hour/min/sec aren't always
    # zero-padded, e.g. "23:1:5:778")
    r"\d{8}-\d{1,2}:\d{1,2}:\d{1,2}:\d+",
    # 081109 203615  (HDFS/BGL-family compact YYMMDD HHMMSS at line start)
    r"^\d{6} \d{6}",
    # 17/06/09 20:10:40  (Spark)
    r"\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}",
    # 03-17 16:13:38.811  (Android, no year)
    r"\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+",
    # [10.30 16:49:06]  (Proxifier, bracketed, no year)
    r"\[\d{2}\.\d{2} \d{2}:\d{2}:\d{2}\]",
    # Jun 14 15:16:01  (RFC 3164 BSD syslog -- Linux/Mac/OpenSSH/Thunderbird)
    r"[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}",
]
_TIMESTAMP_RE = re.compile("|".join(f"(?:{p})" for p in _TIMESTAMP_PATTERNS))

# Last-resort: a standalone 10-digit token in a plausible Unix-epoch
# range (2001-09-09 through 2033-05-18). Only used when nothing above
# matched, and only as a token with clear word boundaries, since a bare
# number is otherwise too weak a signal to trust on its own (e.g. HPC's
# "134681 node-246 ... 1077804742 1 Component State Change...").
_EPOCH_RE = re.compile(r"(?<!\d)(10\d{8}|1[1-9]\d{8}|20\d{8})(?!\d)")

# Standard level words across log4j/syslog/glog/Android-logcat conventions.
_LEVEL_RE = re.compile(
    r"\b(TRACE|DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|CRIT(?:ICAL)?|"
    r"ALERT|EMERG(?:ENCY)?|FATAL)\b",
    re.IGNORECASE,
)
# Android logcat's single-letter level, always sandwiched between two PIDs
# and a Tag: e.g. "1702  2395 D WindowManager:" -- narrow enough context
# (two ints, then the letter, then a word followed by ':') that it won't
# false-positive on ordinary prose.
_ANDROID_LEVEL_RE = re.compile(r"\b\d+\s+\d+\s+([VDIWEF])\s+[\w.$]+:")

# RFC 3164 TAG field: "process[pid]:" or "process(sub)[pid]:"
_SYSLOG_TAG_RE = re.compile(r"\b([\w.\-]+)(?:\([\w.\-]+\))?\[(\d+)\]:")

_SEVERITY_CANON = {
    "trace": "debug", "debug": "debug", "d": "debug",
    "v": "debug", "verbose": "debug",
    "info": "info", "notice": "info", "i": "info",
    "warn": "warning", "warning": "warning", "w": "warning",
    "err": "error", "error": "error", "e": "error",
    "crit": "critical", "critical": "critical",
    "alert": "critical", "emerg": "critical", "emergency": "critical",
    "fatal": "critical", "f": "critical",
}


def extract_timestamp(line):
    m = _TIMESTAMP_RE.search(line[:80])
    if m:
        return m.group(0)
    m = _EPOCH_RE.search(line)
    if m:
        return m.group(0)
    return None


def extract_severity(line):
    m = _ANDROID_LEVEL_RE.search(line)
    if m:
        return _SEVERITY_CANON.get(m.group(1).lower(), "unknown")
    m = _LEVEL_RE.search(line)
    if m:
        return _SEVERITY_CANON.get(m.group(1).lower(), "unknown")
    return None


def extract_process(line):
    """Returns (process_name, pid) from a standard syslog TAG field, or
    (None, None). Only fires on the well-defined 'name[pid]:' shape, so
    it won't misfire on arbitrary bracketed numbers elsewhere in a line."""
    m = _SYSLOG_TAG_RE.search(line)
    if m:
        return m.group(1), m.group(2)
    return None, None


def extract_host(line, timestamp_span_end):
    """RFC 3164 syslog puts HOSTNAME immediately after the timestamp,
    before the TAG field. Only trust this when we actually matched a
    BSD-style (no year, textual month) timestamp, since that's the only
    shape where a hostname is a required, positionally-guaranteed field
    -- guessing a 'host' out of an ISO-timestamp log would be pure
    speculation about a source we know nothing about."""
    if timestamp_span_end is None:
        return None
    rest = line[timestamp_span_end:].lstrip()
    m = re.match(r"^([\w.\-]+)\s", rest)
    if not m:
        return None
    candidate = m.group(1)
    # A syslog TAG ("sshd(pam_unix)[123]:") right after the timestamp
    # means there's no separate hostname field in this line.
    if "[" in candidate or ":" in candidate:
        return None
    return candidate


def profile_line(line):
    """One pass of shape-based tagging over a raw line. Returns a dict
    with whichever of timestamp/severity/host/process/pid it could
    confidently identify -- None for anything it can't."""
    ts_match = _TIMESTAMP_RE.search(line[:80])
    if ts_match:
        timestamp = ts_match.group(0)
    else:
        epoch_match = _EPOCH_RE.search(line)
        timestamp = epoch_match.group(0) if epoch_match else None
    is_bsd_style = bool(ts_match and re.match(r"^[A-Z][a-z]{2}\s", ts_match.group(0)))

    process, pid = extract_process(line)
    host = extract_host(line, ts_match.end() if (ts_match and is_bsd_style) else None)

    return {
        "timestamp": timestamp,
        "severity": extract_severity(line),
        "host": host,
        "process": process,
        "pid": pid,
    }
