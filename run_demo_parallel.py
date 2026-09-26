"""
Multi-core variant of run_demo.py, for GB-scale input.

Why this is safe to parallelize across files with zero coordination:
pipeline._get_drain_miner() already keys every Drain template miner by
source name and never shares state across sources (see pipeline.py's
docstring) -- an Android logcat line and a BGL supercomputer line were
already required to never compete for the same cluster space. That
same isolation means two different source files have nothing to
synchronize: each can be parsed, normalized, and written to its own
output shard in a completely independent worker process. This mirrors
how real log shippers scale (one Filebeat/forwarder process per host,
each pushing its own batches) -- this project was already structured
for that from day one, this file just exercises it.

Each worker writes its own shard under output/shards/<source>/
(all_events.jsonl, elastic_bulk.ndjson, events.parquet) using the same
StreamingWriters class as run_demo.py, so memory per worker stays
O(parquet_batch_size) regardless of that file's size. Splunk/Elastic
ingest multiple shard files natively -- there's no requirement to
merge them into one file before shipping into a SIEM.

The dashboard is the one exception: it's for a human looking at
"what's in this data", and one dashboard per source file (25+ separate
HTML files, none showing the whole picture) actively worked against
that -- there was no single place to look for unified visibility across
every source, which is the entire point of feature (f). Each worker
returns its counters (small Counter objects, not events) instead of
rendering its own dashboard.html, and main() merges all of them into
one output/dashboard.html covering every source in this run.
"""
import glob
import multiprocessing as mp
import os
import time

from dashboard import DashboardAggregator, render_dashboard
from outputs.elasticsearch_mapping import write_elasticsearch_mapping
from pipeline import process_file
from run_demo import StreamingWriters, confidence_bucket
from sniffer import sniff_file

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
SHARD_DIR = os.path.join(OUTPUT_DIR, "shards")


def _process_one_file(filepath):
    """Runs in a worker process. Streams one source file straight to its
    own shard's JSONL/NDJSON/Parquet, never materializing the file's
    events as a list. Returns a small summary dict -- including this
    file's dashboard counters, not its events -- for main() to merge."""
    fname = os.path.basename(filepath)
    source_name = os.path.splitext(fname)[0]
    shard_dir = os.path.join(SHARD_DIR, source_name)
    os.makedirs(shard_dir, exist_ok=True)

    detected = sniff_file(filepath)
    writers = StreamingWriters(
        os.path.join(shard_dir, "events.jsonl"),
        os.path.join(shard_dir, "elastic_bulk.ndjson"),
        os.path.join(shard_dir, "events.parquet"),
        os.path.join(shard_dir, "elastic_docs.ndjson"),
    )

    count = 0
    conf_sum = 0.0
    buckets = {"high": 0, "medium": 0, "low": 0}
    t0 = time.time()
    for event, fmt in process_file(filepath, source_name=source_name):
        count += 1
        conf_sum += event["confidence"]
        buckets[confidence_bucket(event["confidence"])] += 1
        writers.write(event)
    writers.close()
    elapsed = time.time() - t0

    return {
        "file": fname, "source_name": source_name, "detected_format": detected,
        "lines_processed": count, "avg_confidence": round((conf_sum / count) if count else 0.0, 2),
        "confidence_buckets": buckets, "elapsed_sec": round(elapsed, 2),
        "action_counts": writers.dashboard.action_counts,
        "format_counts": writers.dashboard.format_counts,
        "vendor_counts": writers.dashboard.vendor_counts,
        "src_ip_counts": writers.dashboard.src_ip_counts,
        "conf_buckets_dash": writers.dashboard.conf_buckets,
        "sample_rows": writers.dashboard.sample_rows[:5],
    }


def main(workers=None):
    workers = workers or os.cpu_count() or 4
    os.makedirs(SHARD_DIR, exist_ok=True)
    files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*")))

    print("=" * 78)
    print(f"ULPF PARALLEL DEMO RUN -- {len(files)} sources across {workers} worker processes")
    print("=" * 78)

    t0 = time.time()
    with mp.Pool(processes=workers) as pool:
        summaries = pool.map(_process_one_file, files)
    wall_elapsed = time.time() - t0

    total_lines = sum(s["lines_processed"] for s in summaries)
    cpu_seconds = sum(s["elapsed_sec"] for s in summaries)

    for s in summaries:
        print(f"  {s['file']:38s} fmt={s['detected_format']:14s} "
              f"n={s['lines_processed']:6d}  worker_time={s['elapsed_sec']:.2f}s")

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"  Total events        : {total_lines:,}")
    print(f"  Wall-clock time     : {wall_elapsed:.2f}s  ({workers} workers)")
    print(f"  Sum of worker time  : {cpu_seconds:.2f}s  (what a single-threaded run would take)")
    print(f"  Speedup             : {cpu_seconds / wall_elapsed:.2f}x")
    print(f"  Throughput          : {total_lines / wall_elapsed:,.0f} events/sec")

    dashboard_path = os.path.join(OUTPUT_DIR, "dashboard.html")
    merged = DashboardAggregator()
    merged.total = total_lines
    for s in summaries:
        merged.action_counts.update(s["action_counts"])
        merged.format_counts.update(s["format_counts"])
        merged.vendor_counts.update(s["vendor_counts"])
        merged.src_ip_counts.update(s["src_ip_counts"])
        merged.conf_buckets.update(s["conf_buckets_dash"])
        for row in s["sample_rows"]:
            if len(merged.sample_rows) < merged.sample_size:
                merged.sample_rows.append(row)
    render_dashboard(merged, dashboard_path, title=f"ULPF - unified view ({len(files)} sources)")
    mapping_path = os.path.join(OUTPUT_DIR, "elasticsearch_mapping.json")
    write_elasticsearch_mapping(mapping_path)

    print(f"\n  ONE unified dashboard  : {dashboard_path}")
    print(f"  Explicit ES mapping    : {mapping_path}")
    print(f"  Per-source shards      : {SHARD_DIR}/<source_name>/"
          " (events.jsonl, elastic_bulk.ndjson, elastic_docs.ndjson, events.parquet)")


if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else None
    main(workers=n)

# --- Single huge file, not many files ---
# For GB-scale input arriving as ONE file rather than many separate
# source files, see run_demo_bigfile.py -- it finds safe internal
# line-aligned split points and parallelizes across byte-range chunks
# of that one file instead of across files.
