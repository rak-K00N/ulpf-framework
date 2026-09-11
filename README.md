# Universal Log Parsing Prototype (offline, air-gapped, no LLM)

A working prototype of a format-agnostic log ingestion pipeline. It parses
**nine** self-describing/coded formats through dedicated shape extractors,
plus **fifteen** additional real-world formats it has never seen before
through a single statistical fallback path -- all without writing a
parser per source, and without any network calls at any point.

## Why this exists

Every log source encodes roughly the same information (source/destination
IP, port, protocol, action) in a different syntax. Instead of writing a
"Fortinet parser," a "Cisco parser," an "AWS parser," this project parses
by **shape** (JSON / CSV / key=value / CEF / LEEF / RFC 5424 structured
syslog / coded syslog) and normalizes every result into one common
schema. New vendors that happen to emit an already-supported shape need
**zero new code** -- and sources that match *none* of those shapes still
get parsed, via Drain-based template mining plus generic field tagging,
again with **zero new code**.

## Architecture

```
raw log file (plain or gzip-compressed, detected by magic bytes)
     |
     v
sniffer.py            <- detects shape: json / csv / kv_syslog / cef /
     |                     leef / syslog5424 / coded_syslog / unknown
     v
     +-- known shape ------------------------+
     |                                       |
     v                                       v
parsers/*.py                        parsers/drain_fallback.py
 - json_flow.py                      (Drain3 template mining: clusters
 - csv_parser.py                      lines by structural similarity,
 - kv_syslog.py                       splits each into a fixed template +
 - cef.py / leef.py                   variable tokens -- one miner per
 - syslog5424.py                      SOURCE so unrelated formats never
 - coded_syslog.py + codebooks/*.json  share cluster space)
   (only place needing vendor                  |
    knowledge, as DATA not code)                v
                                     parsers/generic_profiler.py
                                      (line-level shape tagging: which of
                                       ~10 published timestamp styles,
                                       which log-level word, RFC 3164
                                       hostname/process/pid position --
                                       plus kv_syslog reused to harvest
                                       any embedded key=value fragments)
     |                                       |
     +-------------------+-------------------+
                         v
              normalizer.py  <- maps every path's output into one common schema
                         v
              normalized event (schema.py) + confidence score
```

## Why no LLM

This is designed for air-gapped environments (typical for firewall/SOC
log processing). Every stage above runs with zero network access:

- 6 of 9 recognized formats are **self-describing** (JSON keys, CSV
  headers, CEF/LEEF's published specs, RFC 5424 structured data, generic
  key=value) -- pure regex/parsing logic, no intelligence needed.
- Formats needing vendor knowledge (Cisco ASA's and Cisco Firepower's
  coded syslog messages, e.g. `%ASA-4-106023` / `%FTD-6-430001`) are
  handled with **codebooks**: vendors publish a stable message-ID ->
  template mapping, stored here as plain JSON files. Adding a new
  coded-syslog vendor means adding a JSON file, not new Python.
- Everything else -- genuinely unrecognized shapes -- falls back to
  **Drain** (via the `drain3` library), a well-published, pre-LLM
  algorithm for automatically splitting log lines into a fixed
  "template" and variable tokens using pure statistics over repeated
  structure, plus a **generic heuristic field-type tagger**
  (`parsers/generic_profiler.py`) that recognizes ~10 widely-published
  timestamp shapes, standard log-level words, and the RFC 3164
  hostname/process/pid TAG field -- all shape rules, none of them
  vendor-specific.

## Results on the provided sample corpus

**Nine recognized shapes** (2,600-2,805 lines each, one held-back 8-line
edge case): 24,550/24,558 events (99.97%) normalized at 0.90-0.98
confidence.

**Fifteen never-seen-before real-world formats** (2,000 lines each, the
public LogHub benchmark corpus: Android, Apache, BGL, Hadoop, HDFS,
HealthApp, HPC, Linux, Mac, OpenSSH, OpenStack, Proxifier, Spark,
Thunderbird, Windows) -- wildly different application, OS, and
supercomputer logs, none matching any shape this project recognizes:

| Source | Timestamp recovered | Host recovered | Avg confidence |
|---|---|---|---|
| Android, Apache, BGL, Hadoop, HDFS, HPC, HealthApp, OpenStack, Proxifier, Spark, Thunderbird, Windows | 100% | n/a (no RFC 3164 hostname field in these shapes) | 0.40-0.49 |
| Linux, Mac, OpenSSH (RFC 3164 BSD syslog) | 100% | 100% | 0.50-0.58 |

**Every single line across all 25 sources parses -- zero drops, zero
exceptions -- with no source-specific code written for any of the 15
unknown ones.** 54,558 total events, 45% at high (shape-recognized)
confidence, 55% at medium (fallback, field-tagged) confidence, effectively
none dropped to bare-template-only.

## What was added in this extension pass

**New recognized shapes:**
1. **LEEF parser** (`parsers/leef.py`) -- IBM's Log Event Extended
   Format, the native output of Check Point, Juniper, and other
   perimeter vendors. Handles LEEF 1.0 and 2.0 (incl. hex-escaped
   delimiters like `x09`).
2. **RFC 5424 structured syslog parser** (`parsers/syslog5424.py`) --
   the modern successor to BSD syslog (F5, Juniper, newer Palo Alto).
   Parses the standard header plus `[sdid key="value"]` blocks.
3. **Transparent gzip support** (`sniffer.open_maybe_compressed`) --
   detected by magic bytes, not extension.
4. **Second coded-syslog vendor** (`codebooks/cisco_firepower.json`,
   prefix `%FTD`) -- added as pure JSON config, no parser changes,
   demonstrating "config not code" for a second vendor.

**Unknown-format fallback overhaul (this is the main event):**
5. **`parsers/generic_profiler.py`** (new) -- the "Heuristic Field-Type
   Tagging" step from the architecture diagram, as its own module.
   Recognizes ~10 published timestamp shapes (ISO w/ comma or dot
   milliseconds, dotted-dash BGL/Thunderbird precision stamps, compact
   `YYMMDD HHMMSS` HDFS-style, `MM-DD HH:MM:SS.mmm` Android, bracketed
   Proxifier, RFC 3164 BSD, a last-resort bare-epoch fallback), standard
   log-level words (`INFO`/`WARN`/`ERROR`/... plus Android's
   single-letter levels in their specific syntactic position), and the
   RFC 3164 `hostname` + `process[pid]:` TAG fields -- all as *shape*
   rules with zero knowledge of which of the 15 sources produced the
   line.
6. **Richer token-level tagging in `drain_fallback.py`** -- `_guess_tag`
   now recognizes IP, IPv6, MAC, UUID, email, URL, filesystem path (Unix
   and Windows), hex, date, time, and generic numbers, not just IP/port.
7. **Fixed a correctness bug in the old delimiter pre-processing**: the
   previous version blanked out `:` and `=` before handing lines to
   Drain, which silently destroyed every timestamp (`15:16:01` ->
   `15 16 01`) and every embedded key=value fragment before they could
   ever be recognized. Only `|` and `,` are normalized now, and real
   key=value fragments are instead recovered losslessly by reusing
   `kv_syslog`'s regex extractor directly against the untouched raw line.
8. **Per-source Drain miners, not one global instance**
   (`pipeline._get_drain_miner`) -- previously a single shared
   `TemplateMiner` was used for *every* unrecognized line regardless of
   source, so an Android logcat line and a BGL supercomputer line would
   compete for the same template-cluster space. Now each source gets
   its own miner, keyed by source name, with **optional on-disk
   persistence** (`drain_state/`) so a source's learned template
   vocabulary keeps improving across separate runs instead of
   restarting cold every time.
9. **Opportunistic key=value harvesting in the fallback path**
   (`normalizer.normalize_drain`) -- even lines with no recognized
   overall shape often embed a few real key=value pairs in prose (e.g.
   Linux's `uid=0 euid=0 rhost=1.2.3.4` inside an auth-failure
   sentence); these are now harvested via the existing generic
   `kv_syslog` regex extractor and merged into `user`/`src_ip`/`dst_ip`
   when present.
10. **Dynamic fallback confidence** -- previously a flat `0.2` for every
    unrecognized line regardless of how much was actually recoverable.
    Now built up from what genuinely fired (timestamp +0.10, severity
    +0.05, host +0.05, process/pid +0.05, user +0.05, IP +0.10), capped
    at 0.75 so it's still clearly below shape-recognized confidence, but
    proportionate to real signal.
11. **New schema fields** (`schema.py`): `severity`, `host`, `process`,
    `pid` -- generic enough to serve any log source, always `None` when
    a shape extractor has nothing to say about them.
11b. **Two more generic fallback improvements, added while proving out
    a brand-new format live (a MikroTik-router-style log the project had
    never seen)**:
    - a **second-line-of-defense timestamp fallback**: if none of
      `generic_profiler`'s ~10 known timestamp shapes match, but Drain
      still isolated a date-shaped or time-shaped *token* purely from
      its position varying line-to-line, that's now used instead of
      giving up on timestamp entirely (catches things like a bare
      `14:22:01` with no date portion).
    - recognition of **`IP:PORT`** and **`SRC:PORT->DST:PORT`** flow
      notation as its own shape (`drain_fallback._guess_tag`) -- common
      across many routers/firewalls (MikroTik, iptables, HAProxy/envoy
      access logs) but structurally different from a bare IP token, so
      it needed its own pattern to split correctly into src/dst ip+port
      rather than being missed entirely.
12. **Sniffer false-positive fixes**: the CSV heuristic was mistaking
    Cisco Firepower's comma-heavy message bodies for a CSV header
    (fixed with shape guards), and the kv_syslog heuristic was
    mistaking a handful of embedded `uid=0`-style fragments inside
    ordinary Linux auth-log prose for a genuine key=value log (fixed
    with a token-ratio threshold: real kv logs are ~100% k=v tokens,
    not ~30%). Also fixed an onboard_source.py bug where the "already
    covered by an existing codebook" check guessed the wrong filename
    and never matched any codebook, including the original Cisco ASA one.
13. **Regression tests** (`tests/test_pipeline.py`) -- now covers all 25
    sample sources, asserting detected format, a confidence floor, and
    correct lineage per file.

## Additional ULPF requirements implemented

**d) Traceability.** `lineage.py` generates a stable `event_id` (a hash
of source path + line number + raw line, so re-running the pipeline
never creates duplicate identities) and attaches a `lineage` block to
every event: source file path, line number, and ingestion timestamp.
An analyst or auditor can always trace a normalized record back to the
exact original line it came from.

**e) Plug-and-play onboarding.** `registry.py` auto-records every source
the pipeline ever sees, tagged with how much work it needed:
- self-describing shapes (json/csv/kv/cef/leef/syslog5424) -> zero code,
  auto-registered
- coded-syslog -> "codebook-driven," just a JSON config
- unrecognized -> routed through the Drain fallback automatically, no
  action required

`onboard_source.py` is a CLI a team member runs against a brand-new
source's sample before wiring it in:
```bash
python3 onboard_source.py --sample new_source_sample.log --name my-new-firewall
```
It tells you immediately whether the source needs zero code (self-
describing shape), a codebook (and *scaffolds one automatically* with
every message code it found in the sample, ready to fill in, or tells
you it's already covered by an existing codebook), or nothing at all --
truly unrecognized shapes report that Drain's fallback will handle it
with no action needed, plus a note on how much sample volume helps
Drain's clustering converge.

**f) Unified visibility.** `dashboard.py` generates one self-contained
`dashboard.html` -- charts drawn in plain SVG, data embedded inline, no
external JS library or CDN, no server. Open it in any browser. Stays a
~15KB file even summarizing 54,000+ events across 25 sources. Shows
events by action/format/vendor, top source IPs, confidence distribution,
and a sample event table.

**g) SIEM / Data Lake integration.** `outputs/` has two adapters:
- `elastic_bulk.py` writes the exact NDJSON shape Elasticsearch's/
  OpenSearch's `_bulk` API expects, using `event_id` as the document ID
  so re-ingestion is idempotent, not duplicating.
- `parquet_writer.py` writes columnar Parquet (via pyarrow) for data
  lake platforms (S3 + Athena, Spark, Delta Lake), with the nested
  `lineage` block flattened into queryable columns.

Both run fully offline; the output files are meant to be moved into the
air-gapped boundary's SIEM/lake however your environment allows.

## Running it

```bash
pip install drain3 pyarrow
python3 run_demo.py
```

This processes every file in `samples/` (25 sources, ~54,500 lines,
including a gzip-compressed one, transparently), prints a per-file
report plus sections demonstrating traceability and the source registry,
and writes to `output/`: `all_events.jsonl`, `dashboard.html`,
`elastic_bulk.ndjson`, and `events.parquet`.

To onboard a new source before wiring it into the real pipeline:
```bash
python3 onboard_source.py --sample /path/to/sample.log --name my-source
```

To sanity-check the pipeline after changing a parser, the sniffer, or a
codebook:
```bash
python3 tests/test_pipeline.py
```

## Known simplifications (good to mention if asked)

- CEF/LEEF pipe-escaping (`\|` inside a field) isn't handled -- fine for
  this corpus, would need a stricter tokenizer for production use.
- The coded-syslog codebooks only cover the message codes present in
  each sample file; extending them to full vendor coverage is scraping
  the vendor's published message reference into more JSON entries, not
  new parsing logic.
- Fallback-path `user`/`host`/IP fields are best-effort: they come from
  generic shape rules (RFC 3164 field position, common k=v key aliases),
  not from knowing what any given source's fields actually mean. A field
  like `user: "0"` recovered from `uid=0` in a line with no separate
  username is technically the uid, not a username -- correctly low
  confidence, and the raw line is always kept alongside it so nothing is
  silently misrepresented.
- Drain state persistence (`drain_state/`) is a simple per-source JSON
  snapshot on local disk; for genuinely distributed/multi-node ingestion
  at Big-Data volume, this would need to move to a shared store.
- Gzip support covers whole-file compression detected by magic bytes;
  it does not (yet) handle multi-stream/concatenated gzip archives or
  other compression schemes (zstd, bzip2).

## Stretch idea (not built here)

An optional LLM step could sit *after* Drain, only to *label* what a
variable token semantically means when heuristics are unsure (e.g. "is
this a device name or a username") -- generated once per template and
cached, never in the per-line hot path. Deliberately left out here to
keep the whole system air-gapped end to end.
