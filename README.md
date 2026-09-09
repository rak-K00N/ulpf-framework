# Universal Log Parsing Prototype (offline, air-gapped, no LLM)

A working prototype of a format-agnostic log ingestion pipeline. It parses
five different real firewall/cloud log formats through one shared
pipeline, without writing a parser per vendor, and without any network
calls at any point.

## Why this exists

Every log source encodes roughly the same information (source/destination
IP, port, protocol, action) in a different syntax. Instead of writing a
"Fortinet parser," a "Cisco parser," an "AWS parser," this project parses
by **shape** (JSON / CSV / key=value / CEF / coded syslog) and normalizes
every result into one common schema. New vendors that happen to emit an
already-supported shape need **zero new code**.

## Architecture

```
raw log file
     |
     v
sniffer.py            <- detects shape: json / csv / kv_syslog / cef / coded_syslog / unknown
     |
     v
parsers/*.py           <- one extractor per SHAPE, not per vendor
     |                     - json_flow.py   (any JSON-emitting source)
     |                     - csv_parser.py  (header row IS the schema)
     |                     - kv_syslog.py   (generic key=value tokenizer)
     |                     - cef.py         (published CEF spec, mechanical)
     |                     - coded_syslog.py + codebooks/*.json
     |                        (only place that needs vendor knowledge,
     |                         expressed as DATA not code)
     |                     - drain_fallback.py (statistical template
     |                        mining for anything unrecognized -- no LLM)
     v
normalizer.py           <- maps every shape's output into one common schema
     v
normalized event (schema.py) + confidence score
```

## Why no LLM

This is designed for air-gapped environments (typical for firewall/SOC
log processing). Every stage above runs with zero network access:

- 4 of 5 real-world formats tested are **self-describing** (JSON keys,
  CSV headers, CEF's published spec, generic key=value) -- pure regex/
  parsing logic, no intelligence needed.
- The one format needing vendor knowledge (Cisco ASA's coded syslog
  messages, e.g. `%ASA-4-106023`) is handled with a **codebook**:
  Cisco publish a stable message-ID -> template mapping, stored here as
  a plain JSON file (`codebooks/cisco_asa.json`). Adding a new coded-
  syslog vendor means adding a JSON file, not new Python.
- Anything genuinely unrecognized falls back to **Drain** (via the
  `drain3` library), a well-published, pre-LLM algorithm for
  automatically splitting log lines into a fixed "template" and
  variable tokens using pure statistics over repeated structure. Cheap
  shape heuristics (regex for IP-shaped / port-shaped / date-shaped)
  then guess at what the variables mean.

## Results on the provided sample corpus

| File | Detected format | Lines | Avg confidence |
|---|---|---|---|
| 01_fortinet_syslog.log | kv_syslog | 2,805 | 0.95 |
| 02_fortinet_cef.log | cef | 2,778 | 0.95 |
| 03_cisco_asa_syslog.log | coded_syslog | 2,788 | 0.90 |
| 04_cloud_flow_logs.json | json | 2,786 | 0.98 |
| 05_firewall_export.csv | csv | 2,788 | 0.98 |
| 06_unknown_format.log (synthetic, held back on purpose) | unknown -> Drain fallback | 8 | 0.20 |

13,945 / 13,953 events (99.9%) normalized at high confidence, entirely
offline, with the one deliberately-unseen format correctly flagged as
low-confidence rather than silently mis-parsed or dropped.

## Additional ULPF requirements implemented

**d) Traceability.** `lineage.py` generates a stable `event_id` (a hash
of source path + line number + raw line, so re-running the pipeline
never creates duplicate identities) and attaches a `lineage` block to
every event: source file path, line number, and ingestion timestamp.
An analyst or auditor can always trace a normalized record back to the
exact original line it came from.

**e) Plug-and-play onboarding.** `registry.py` auto-records every source
the pipeline ever sees, tagged with how much work it needed:
- self-describing shapes (json/csv/kv/cef) -> zero code, auto-registered
- coded-syslog -> "codebook-driven," just a JSON config
- unrecognized -> routed through the Drain fallback automatically

`onboard_source.py` is a CLI a team member runs against a brand-new
source's sample before wiring it in:
```bash
python3 onboard_source.py --sample new_source_sample.log --name my-new-firewall
```
It tells you immediately whether the source needs zero code (self-
describing shape), a codebook (and *scaffolds one automatically* with
every message code it found in the sample, ready to fill in), or nothing
at all (unrecognized shapes fall back to Drain with no action needed).

**f) Unified visibility.** `dashboard.py` generates one self-contained
`dashboard.html` -- charts drawn in plain SVG, data embedded inline, no
external JS library or CDN, no server. Open it in any browser. Shows
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

This processes every file in `samples/`, prints a per-file report plus
sections demonstrating traceability and the source registry, and writes
to `output/`: `all_events.jsonl`, `dashboard.html`, `elastic_bulk.ndjson`,
and `events.parquet`.

To onboard a new source before wiring it into the real pipeline:
```bash
python3 onboard_source.py --sample /path/to/sample.log --name my-source
```

## Known simplifications (good to mention if asked)

- CEF pipe-escaping (`\|` inside a field) isn't handled -- fine for this
  corpus, would need a stricter tokenizer for production CEF.
- The coded-syslog codebook only covers the 8 message codes present in
  the sample file; extending it to full Cisco ASA coverage is scraping
  Cisco's published message reference into more JSON entries, not new
  parsing logic.
- Drain's built-in `extra_delimiters` option has a bug where non-word
  delimiters (like `|`) are used unescaped inside a regex; this project
  works around it by normalizing delimiters to whitespace before handing
  lines to drain3 (see `parsers/drain_fallback.py`).
- With only 8 lines, Drain's online clustering hasn't fully converged,
  so some unknown-format lines get variables extracted and some don't --
  this stabilizes quickly with realistic log volume (thousands of lines).

## Stretch idea (not built here)

An optional LLM step could sit *after* Drain, only to *label* what a
variable token semantically means when heuristics are unsure (e.g. "is
this a device name or a username") -- generated once per template and
cached, never in the per-line hot path. Deliberately left out here to
keep the whole system air-gapped end to end.
