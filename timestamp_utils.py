"""
Every normalize_* function in normalizer.py hands back a "timestamp"
field, but they don't agree on its shape at all -- across the 25 sample
formats this project ships with, the raw values look like:

    2026-08-31 09:12:03            2015-10-18 18:01:47,978
    2025-08-31T09:00:00+00:00      081109 203615
    Aug 31 2026 09:15:02           20171223-22:15:29:606
    Aug 31 09:12:03  (no year)     2005.06.03  (date only, no time)
    03-17 16:13:38.811 (no year)   1077804742  (bare unix epoch)
    [10.30 16:49:06]   (no year)   17/06/09 20:10:40

That's not a cosmetic problem: Elasticsearch/Kibana can only treat a
field as a proper `date` type if every document's value parses under
one consistent format. A field that's sometimes ISO-8601, sometimes a
year-less BSD string, sometimes a bare epoch number gets typed as
`text` by dynamic mapping (or, worse, locks onto whichever shape
appeared in the first document and then fails to index every document
after it that doesn't match) -- either way, no date histogram, no
time-series panel, nothing Kibana's dashboard tooling (AI-assisted or
not) can build a "results over time" view from. This module is the
fix: every shape above gets normalized to the same strict ISO-8601 UTC
form (e.g. "2026-08-31T09:12:03.000Z") before an event ever leaves the
pipeline.

Several source shapes carry no year at all (BSD syslog, Android,
Proxifier). The standard heuristic used by rsyslog and Logstash's own
date filter is applied here too: assume the current year, unless that
would put the timestamp in the future, in which case assume the
previous year -- this handles the ordinary case of a Dec 31 line still
being processed in early January without silently mis-dating it a year
ahead.

One real, disclosed limitation: BGL and Thunderbird's ".2005.06.03"
shaped field is a bare calendar date with no time-of-day component at
all in that particular token (the fuller sub-second timestamp some BGL
lines also carry elsewhere is a separate, not-currently-extracted
field -- see generic_profiler.py's leftmost-match caveat). Normalizing
it still produces a valid, correctly-typed `date` value
(YYYY-MM-DDT00:00:00.000Z), just at day-level granularity rather than
second-level for those two formats specifically.
"""
import re
from datetime import datetime, timezone

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def _infer_year(month, day, now):
    now = now or datetime.now(timezone.utc)
    year = now.year
    try:
        candidate = datetime(year, month, day, tzinfo=timezone.utc)
    except ValueError:
        return year
    if candidate.date() > now.date():
        year -= 1
    return year


def _mk(year, month, day, hour=0, minute=0, second=0, microsecond=0):
    try:
        return datetime(year, month, day, hour, minute, second, microsecond, tzinfo=timezone.utc)
    except ValueError:
        return None


def _fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


_PATTERNS = []  # (compiled_regex, lambda match, now: datetime|None)


def _p(pattern, fn):
    _PATTERNS.append((re.compile(pattern), fn))


# ISO 8601 -- "T" or space separator, optional . or , fractional seconds,
# optional Z / +HH:MM offset. Covers fortinet/cloud-flow/csv/syslog5424/
# hadoop/openstack/windows shapes.
_p(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,](\d+))?(?:Z|[+-]\d{2}:?\d{2})?$",
   lambda m, now: _mk(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]),
                       int((m[7] or "0").ljust(6, "0")[:6])))

# "Aug 31 2026 09:15:02" -- BSD month name WITH explicit year
# (checkpoint LEEF / cisco firepower coded_syslog).
_p(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$",
   lambda m, now: _mk(int(m[3]), _MONTHS[m[1]], int(m[2]), int(m[4]), int(m[5]), int(m[6]))
   if m[1] in _MONTHS else None)

# "Aug 31 09:12:03" / "Jun 14 15:16:01" / "Jul  1 09:00:55" -- RFC 3164
# BSD syslog, no year (linux/mac/openssh/apache/cef+leef prefixes).
_p(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$",
   lambda m, now: _mk(_infer_year(_MONTHS[m[1]], int(m[2]), now), _MONTHS[m[1]], int(m[2]),
                       int(m[3]), int(m[4]), int(m[5])) if m[1] in _MONTHS else None)

# "03-17 16:13:38.811" -- Android, MM-DD, no year.
_p(r"^(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d+)$",
   lambda m, now: _mk(_infer_year(int(m[1]), int(m[2]), now), int(m[1]), int(m[2]),
                       int(m[3]), int(m[4]), int(m[5]), int(m[6].ljust(6, "0")[:6])))

# "[10.30 16:49:06]" -- Proxifier, bracketed MM.DD, no year.
_p(r"^\[(\d{2})\.(\d{2}) (\d{2}):(\d{2}):(\d{2})\]$",
   lambda m, now: _mk(_infer_year(int(m[1]), int(m[2]), now), int(m[1]), int(m[2]),
                       int(m[3]), int(m[4]), int(m[5])))

# "17/06/09 20:10:40" -- Spark, YY/MM/DD.
_p(r"^(\d{2})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})$",
   lambda m, now: _mk(2000 + int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6])))

# "081109 203615" -- HDFS-family compact YYMMDD HHMMSS.
_p(r"^(\d{2})(\d{2})(\d{2}) (\d{2})(\d{2})(\d{2})$",
   lambda m, now: _mk(2000 + int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6])))

# "20171223-22:15:29:606" -- HealthApp, YYYYMMDD-HH:MM:SS:mmm.
_p(r"^(\d{4})(\d{2})(\d{2})-(\d{1,2}):(\d{1,2}):(\d{1,2}):(\d+)$",
   lambda m, now: _mk(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]),
                       int(m[7].ljust(3, "0")[:3]) * 1000))

# "2005.06.03" / "2005.11.09" -- BGL/Thunderbird date-only field. See
# module docstring: day-level granularity only, disclosed limitation.
_p(r"^(\d{4})\.(\d{2})\.(\d{2})$",
   lambda m, now: _mk(int(m[1]), int(m[2]), int(m[3])))

# bare 10-digit unix epoch seconds (HPC).
_p(r"^\d{10}$",
   lambda m, now: datetime.fromtimestamp(int(m[0]), tz=timezone.utc))


def normalize_timestamp(raw, now=None):
    """Returns a strict ISO-8601 UTC string ('...T...Z'), or None if raw
    is empty or doesn't match any known shape. None is deliberate, not
    an error swallowed silently -- a field Elasticsearch can't type as
    `date` is worse than a field that's sometimes absent, and the
    original text is never actually lost: it's still in event['raw']."""
    if not raw:
        return None
    raw = raw.strip()
    for regex, fn in _PATTERNS:
        m = regex.match(raw)
        if m:
            dt = fn(m, now)
            if dt:
                return _fmt(dt)
    return None
