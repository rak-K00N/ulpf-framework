"""
Runs the full pipeline against every file in samples/ and demonstrates
all four of: traceability (d), plug-and-play onboarding (e), unified
visibility (f), and SIEM/data-lake integration (g).

No network calls anywhere in this file or anything it imports.

--- Scaling note ---
The previous version of this file built one Python list of every
normalized event (`all_events.append(event)`) purely so it could hand
that list to the dashboard, the Elasticsearch bulk writer, and the
Parquet writer afterward. That's fine for the 54K-line sample corpus,
but it means memory usage grows linearly with input size -- at GB-scale
input (millions of events) that list, not the parsing engine, is what
exhausts RAM first. pipeline.process_file() was already a generator;
this version keeps it that way end to end: every event is written to
all four sinks (JSONL, dashboard aggregator, Elasticsearch bulk NDJSON,
Parquet) the moment it's produced, then discarded. Memory stays
O(parquet_batch_size), a constant, regardless of how many events or how
many gigabytes of input files are processed.
"""
import glob
import json
import os

import pyarrow as pa
import pyarrow.parquet as pq

import pipeline
from pipeline import process_file
from sniffer import sniff_file
import registry
from codebook import review_summary
from dashboard import DashboardAggregator, render_dashboard
from outputs.parquet_writer import _flatten, PARQUET_SCHEMA
from outputs.elasticsearch_mapping import write_elasticsearch_mapping

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
PARQUET_BATCH_SIZE = 10_000


def confidence_bucket(c):
    if c >= 0.8:
        return "high"
    if c >= 0.4:
        return "medium"
    return "low"


class StreamingWriters:
    """
    Opens all four output sinks once for the whole run and feeds every
    event to each of them in a single pass. Nothing here ever holds more
    than one Parquet batch (default 10,000 rows) in memory at a time --
    the JSONL and NDJSON writers are pure line-at-a-time appends, and the
    dashboard only keeps running Counters plus a capped 25-row sample
    (see dashboard.DashboardAggregator).
    """

    def __init__(self, jsonl_path, ndjson_path, parquet_path, docs_ndjson_path,
                 index_name="ulpf-events", parquet_batch_size=PARQUET_BATCH_SIZE):
        self.jsonl_f = open(jsonl_path, "w")
        self.ndjson_f = open(ndjson_path, "w")
        self.docs_f = open(docs_ndjson_path, "w")
        self.parquet_path = parquet_path
        self.index_name = index_name
        self.parquet_batch_size = parquet_batch_size
        self._parquet_writer = None
        self._parquet_batch = []
        self.dashboard = DashboardAggregator()
        self.count = 0

    def write(self, event):
        # Kibana's dashboard/visualization tooling (AI-assisted or not)
        # defaults to looking for a field literally named "@timestamp"
        # (the ECS convention) to offer as the time field -- without it,
        # a data view has no time field to build a date histogram or
        # "last 24 hours" panel from at all, regardless of whether
        # "timestamp" itself is a valid date. Added to every JSON output
        # (not Parquet, which Kibana doesn't ingest directly) alongside
        # the original "timestamp" field, not instead of it.
        event = dict(event)
        event["@timestamp"] = event.get("timestamp")

        self.jsonl_f.write(json.dumps(event) + "\n")

        # Elasticsearch/OpenSearch _bulk NDJSON: action line + doc line,
        # using event_id as _id so re-ingesting the same file overwrites
        # rather than duplicates (idempotent ingestion). This is for the
        # _bulk API specifically -- NOT the same thing as a plain NDJSON
        # of documents, and Kibana's own "Upload a file" data visualizer
        # rejects it for exactly that reason: it expects one JSON
        # document per line, with no interleaved index-action lines.
        action = {"index": {"_index": self.index_name, "_id": event.get("event_id")}}
        self.ndjson_f.write(json.dumps(action) + "\n")
        self.ndjson_f.write(json.dumps(event) + "\n")

        # Plain document-per-line NDJSON, specifically for Kibana's file
        # upload / ML data visualizer (or any tool that expects raw
        # documents, not a _bulk request body).
        self.docs_f.write(json.dumps(event) + "\n")

        self._parquet_batch.append(_flatten(event))
        if len(self._parquet_batch) >= self.parquet_batch_size:
            self._flush_parquet()

        self.dashboard.add(event)
        self.count += 1

    def _flush_parquet(self):
        if not self._parquet_batch:
            return
        if self._parquet_writer is None:
            self._parquet_writer = pq.ParquetWriter(self.parquet_path, PARQUET_SCHEMA, compression="snappy")
        table = pa.Table.from_pylist(self._parquet_batch, schema=PARQUET_SCHEMA)
        self._parquet_writer.write_table(table)
        self._parquet_batch = []

    def close(self):
        self._flush_parquet()
        if self._parquet_writer is None:
            # No events at all (or fewer than one flush) -- still emit a
            # valid, empty-but-correctly-typed Parquet file rather than
            # silently producing nothing.
            self._parquet_writer = pq.ParquetWriter(self.parquet_path, PARQUET_SCHEMA, compression="snappy")
        self._parquet_writer.close()
        self.jsonl_f.close()
        self.ndjson_f.close()
        self.docs_f.close()


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    jsonl_path = os.path.join(OUTPUT_DIR, "all_events.jsonl")
    ndjson_path = os.path.join(OUTPUT_DIR, "elastic_bulk.ndjson")
    docs_path = os.path.join(OUTPUT_DIR, "elastic_docs.ndjson")
    parquet_path = os.path.join(OUTPUT_DIR, "events.parquet")
    dashboard_path = os.path.join(OUTPUT_DIR, "dashboard.html")
    mapping_path = os.path.join(OUTPUT_DIR, "elasticsearch_mapping.json")

    files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*")))
    overall_stats = {"total": 0, "high": 0, "medium": 0, "low": 0}
    per_file_summaries = []

    writers = StreamingWriters(jsonl_path, ndjson_path, parquet_path, docs_path)

    for filepath in files:
        fname = os.path.basename(filepath)
        source_name = os.path.splitext(fname)[0]
        detected = sniff_file(filepath)

        count = 0
        conf_sum = 0.0
        example_event = None
        buckets = {"high": 0, "medium": 0, "low": 0}

        for event, fmt in process_file(filepath, source_name=source_name):
            count += 1
            conf_sum += event["confidence"]
            bucket = confidence_bucket(event["confidence"])
            buckets[bucket] += 1
            overall_stats[bucket] += 1
            overall_stats["total"] += 1
            if example_event is None:
                example_event = event
            writers.write(event)

        avg_conf = (conf_sum / count) if count else 0.0
        per_file_summaries.append({
            "file": fname, "detected_format": detected,
            "lines_processed": count, "avg_confidence": round(avg_conf, 2),
            "confidence_buckets": buckets, "example_event": example_event,
        })

    writers.close()

    # ---- (d) traceability proof: pick one event, show its lineage ----
    print("=" * 78)
    print("UNIVERSAL LOG PARSER - DEMO RUN (100% offline, no LLM, no network)")
    print("=" * 78)

    for s in per_file_summaries:
        print(f"\nFile: {s['file']}")
        print(f"  Detected format : {s['detected_format']}")
        print(f"  Lines processed : {s['lines_processed']}")
        print(f"  Avg confidence  : {s['avg_confidence']}")
        print(f"  Confidence mix  : high={s['confidence_buckets']['high']} "
              f"medium={s['confidence_buckets']['medium']} "
              f"low={s['confidence_buckets']['low']}")

    print("\n" + "=" * 78)
    print("(d) TRACEABILITY - example event with full lineage")
    print("=" * 78)
    example = per_file_summaries[0]["example_event"]
    print(json.dumps(example, indent=2))

    print("\n" + "=" * 78)
    print("(e) PLUG-AND-PLAY ONBOARDING - source registry after this run")
    print("=" * 78)
    registry.print_registry()

    print("\n" + "=" * 78)
    print("(h) SELF-WRITING PARSER CODEBOOK - promoting stable templates")
    print("=" * 78)
    codebook, promoted = pipeline.promote_learned_codebook()
    print(f"  Codebook now holds {len(codebook.entries)} promoted templates "
          f"({len(promoted)} newly promoted this run):")
    print(review_summary(promoted))
    if promoted:
        print(f"\n  Saved to: {pipeline.CODEBOOK_PATH}")
        print("  Copy this one file to another air-gapped machine to recognize")
        print("  these formats instantly there too -- no re-learning required.")

    print("\n" + "=" * 78)
    print("OVERALL")
    print("=" * 78)
    total = overall_stats["total"]
    for bucket in ("high", "medium", "low"):
        n = overall_stats[bucket]
        pct = (100 * n / total) if total else 0
        print(f"  {bucket:7s} confidence     : {n:6d}  ({pct:.1f}%)")

    # ---- (f) unified visibility dashboard ----
    render_dashboard(writers.dashboard, dashboard_path)
    print(f"\n(f) Unified visibility dashboard written to: {dashboard_path}")
    print("    Open it directly in any browser -- no server needed.")

    # ---- (g) SIEM / data lake output adapters ----
    write_elasticsearch_mapping(mapping_path)
    print(f"\n(g) SIEM-ready Elasticsearch _bulk file written: {ndjson_path} "
          f"({writers.count} events)")
    print(f"(g) Plain-document NDJSON (for Kibana's 'Upload a file' / ML data "
          f"visualizer, which rejects _bulk-format files): {docs_path}")
    print(f"(g) Explicit index mapping (correct date/ip/keyword typing -- PUT this "
          f"before bulk-loading, don't rely on dynamic mapping): {mapping_path}")
    print(f"(g) Data-lake-ready Parquet file written: {parquet_path} "
          f"({writers.count} events)")

    print(f"\n  Full JSONL output also available at: {jsonl_path}")


if __name__ == "__main__":
    main()
