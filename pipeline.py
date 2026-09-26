"""
The whole point of the project: process_file() takes any log file and
returns normalized events, without the caller ever needing to know or
specify what format it's in.

Also responsible for two things added for the ULPF requirements:
  - lineage stamping on every event (requirement d: traceability)
  - updating the source registry as new sources are seen
    (requirement e: plug-and-play onboarding)
"""
import hashlib
import os

from parsers import cef, coded_syslog, csv_parser, json_flow, kv_syslog, leef, syslog5424
from parsers.drain_fallback import DrainFallbackParser
import normalizer
from lineage import make_lineage
from sniffer import sniff_file, sniff_line, open_maybe_compressed
from registry import record_source_seen
from codebook import LearnedCodebook, promote_stable_clusters

# Each *source* gets its own Drain miner instance, not one shared globally.
# Wildly different unknown formats (an Android logcat line and a BGL
# supercomputer line share nothing structurally) must never compete for
# the same template-cluster space -- that would both slow convergence and
# produce meaningless cluster_ids. Keyed by source_name so the same
# source seen across multiple files/runs keeps accumulating one template
# vocabulary, matching the "gets better as you onboard more of a source's
# traffic" story rather than starting cold every call.
_drain_miners = {}
_DRAIN_STATE_DIR = os.path.join(os.path.dirname(__file__), "drain_state")

# Where a promoted codebook lives -- deliberately its own directory, NOT
# codebooks/ (that name is already taken: parsers/coded_syslog.py uses
# codebooks/*.json for hand-authored vendor message-code tables, a
# completely different, pre-existing concept). Also deliberately NOT
# inside output/, which gets wiped and regenerated every demo run. This
# is the durable, portable artifact: copy this one file to another
# air-gapped machine and it recognizes every format promoted here
# without re-learning any of it. Auto-loaded on startup if present; see
# promote_learned_codebook() for how new entries get added to it.
CODEBOOK_PATH = os.path.join(os.path.dirname(__file__), "learned_codebooks", "learned_codebook.json")

_shared_codebook = None


def _load_shared_codebook():
    global _shared_codebook
    if _shared_codebook is None:
        if os.path.exists(CODEBOOK_PATH):
            _shared_codebook = LearnedCodebook.load(CODEBOOK_PATH)
        else:
            _shared_codebook = LearnedCodebook()
    return _shared_codebook


def _get_drain_miner(source_key, persist=True):
    if source_key not in _drain_miners:
        persistence_path = None
        if persist:
            os.makedirs(_DRAIN_STATE_DIR, exist_ok=True)
            digest = hashlib.sha256(source_key.encode()).hexdigest()[:16]
            persistence_path = os.path.join(_DRAIN_STATE_DIR, f"{digest}.json")
        _drain_miners[source_key] = DrainFallbackParser(
            persistence_path=persistence_path, codebook=_load_shared_codebook())
    return _drain_miners[source_key]


def promote_learned_codebook(min_occurrences=None):
    """Call after a run to promote every stable Drain cluster, across
    every source touched this run, into the shared codebook and save it
    back to CODEBOOK_PATH. Returns (codebook, all_promoted) where
    all_promoted is a list of (source_name, template, sample_count) --
    exactly what a human-facing review printout needs (see run_demo.py).
    Safe to call even if nothing new was promoted."""
    codebook = _load_shared_codebook()
    all_promoted = []
    kwargs = {} if min_occurrences is None else {"min_occurrences": min_occurrences}
    for source_key, drain_parser in _drain_miners.items():
        codebook, promoted = promote_stable_clusters(
            drain_parser, source_key, existing=codebook, **kwargs)
        all_promoted.extend((source_key, t, c) for t, c in promoted)
    if all_promoted:
        os.makedirs(os.path.dirname(CODEBOOK_PATH), exist_ok=True)
        codebook.save(CODEBOOK_PATH)
    return codebook, all_promoted


def process_file(filepath, source_name=None, persist_drain_state=True):
    """
    Yields (normalized_event, detected_format) for every line/row in
    filepath. This is the only function the outside world needs to call.
    """
    fmt = sniff_file(filepath)
    source_key = source_name or filepath
    record_source_seen(source_key, filepath, fmt)

    if fmt == "csv":
        for i, row in enumerate(csv_parser.parse_file(filepath), start=1):
            raw_line = ",".join(row.values())
            lineage = make_lineage(filepath, i, raw_line, source_name)
            yield normalizer.finalize(normalizer.normalize_csv(row, raw_line, lineage)), fmt
        return

    drain = _get_drain_miner(source_key, persist=persist_drain_state) if fmt == "unknown" else None

    with open_maybe_compressed(filepath) as f:
        for i, line in enumerate(f, start=1):
            line = line.rstrip("\n")
            if not line.strip():
                continue
            lineage = make_lineage(filepath, i, line, source_name)
            yield process_line(line, fmt, lineage, drain=drain), fmt


def process_line(line, fmt_hint=None, lineage=None, drain=None):
    """Processes a single line, given an already-known format hint."""
    fmt = fmt_hint or sniff_line(line)

    if fmt == "json":
        fields = json_flow.parse_line(line)
        if fields is not None:
            return normalizer.finalize(normalizer.normalize_json_flow(fields, line, lineage))

    elif fmt == "leef":
        fields = leef.parse_line(line)
        if fields is not None:
            return normalizer.finalize(normalizer.normalize_leef(fields, line, lineage))

    elif fmt == "cef":
        fields = cef.parse_line(line)
        if fields is not None:
            return normalizer.finalize(normalizer.normalize_cef(fields, line, lineage))

    elif fmt == "syslog5424":
        fields = syslog5424.parse_line(line)
        if fields is not None:
            return normalizer.finalize(normalizer.normalize_syslog5424(fields, line, lineage))

    elif fmt == "coded_syslog":
        fields = coded_syslog.parse_line(line)
        if fields is not None:
            return normalizer.finalize(normalizer.normalize_coded_syslog(fields, line, lineage))

    elif fmt == "kv_syslog":
        fields = kv_syslog.parse_line(line)
        if fields:
            return normalizer.finalize(normalizer.normalize_kv_fortinet(fields, line, lineage))

    # nothing matched, or the shape-specific parser failed on this line
    # -> fall back to statistical template mining instead of dropping it
    drain = drain or _get_drain_miner("_adhoc_", persist=False)
    drain_result = drain.parse_line(line)
    return normalizer.finalize(normalizer.normalize_drain(drain_result, line, lineage))
