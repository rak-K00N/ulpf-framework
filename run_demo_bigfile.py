"""
python3 run_demo_bigfile.py <path-to-one-huge-log-file> [num_workers]

Splits ONE large file into num_workers line-aligned byte ranges (see
bigfile_chunking.find_chunk_boundaries), processes each range in its own
worker process, then merges the per-chunk shards back into single
all_events.jsonl / elastic_bulk.ndjson / events.parquet / dashboard.html
files under output/bigfile/<source_name>/ -- same output shape as
run_demo.py, just built from N parallel workers instead of one process.

This is the answer to "what if the GB-scale input is a single file, not
many source files": run_demo_parallel.py already parallelizes across
separate files for free (Drain miners are isolated per source already);
this script does the equivalent for one file by finding safe internal
split points instead.
"""
import glob
import json
import multiprocessing as mp
import os
import shutil
import sys
import time

import pyarrow as pa
import pyarrow.parquet as pq

from bigfile_chunking import (
    find_chunk_boundaries, materialize_plain_file,
    process_chunk_csv, process_chunk_generic,
)
from dashboard import DashboardAggregator, render_dashboard
from outputs.parquet_writer import PARQUET_SCHEMA
from outputs.elasticsearch_mapping import write_elasticsearch_mapping
from registry import record_source_seen
from run_demo import StreamingWriters
from sniffer import sniff_file

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")
BIGFILE_DIR = os.path.join(OUTPUT_DIR, "bigfile")


def _worker(args):
    (actual_path, fmt, chunk, chunk_idx, source_name,
     header_fields, source_path_for_lineage, shard_dir) = args
    os.makedirs(shard_dir, exist_ok=True)
    writers = StreamingWriters(
        os.path.join(shard_dir, "events.jsonl"),
        os.path.join(shard_dir, "elastic_bulk.ndjson"),
        os.path.join(shard_dir, "events.parquet"),
        os.path.join(shard_dir, "elastic_docs.ndjson"),
    )
    t0 = time.time()
    if fmt == "csv":
        gen = process_chunk_csv(actual_path, chunk, header_fields, source_name, source_path_for_lineage)
    else:
        gen = process_chunk_generic(actual_path, fmt, chunk, source_name, source_path_for_lineage)

    for event in gen:
        writers.write(event)
    writers.close()
    elapsed = time.time() - t0

    return {
        "chunk_idx": chunk_idx,
        "count": writers.count,
        "elapsed": round(elapsed, 2),
        "action_counts": writers.dashboard.action_counts,
        "format_counts": writers.dashboard.format_counts,
        "vendor_counts": writers.dashboard.vendor_counts,
        "src_ip_counts": writers.dashboard.src_ip_counts,
        "conf_buckets": writers.dashboard.conf_buckets,
        "sample_rows": writers.dashboard.sample_rows[:5],
        "shard_dir": shard_dir,
    }


def _merge_line_files(shard_paths_in_order, out_path):
    with open(out_path, "wb") as out_f:
        for p in shard_paths_in_order:
            with open(p, "rb") as in_f:
                shutil.copyfileobj(in_f, out_f)


def _merge_parquet(shard_paths_in_order, out_path):
    writer = pq.ParquetWriter(out_path, PARQUET_SCHEMA, compression="snappy")
    try:
        for p in shard_paths_in_order:
            pf = pq.ParquetFile(p)
            for batch in pf.iter_batches(batch_size=10_000):
                writer.write_table(pa.Table.from_batches([batch], schema=PARQUET_SCHEMA))
    finally:
        writer.close()


def process_large_file(filepath, num_workers=None, source_name=None, keep_shards=False):
    num_workers = num_workers or os.cpu_count() or 4
    source_name = source_name or os.path.splitext(os.path.basename(filepath))[0]

    print("=" * 78)
    print(f"ULPF SINGLE-FILE CHUNKED RUN -- {filepath}")
    print("=" * 78)

    file_size = os.path.getsize(filepath)
    print(f"  Input size          : {file_size / (1024*1024):,.1f} MB")

    t_decompress0 = time.time()
    actual_path, is_temp = materialize_plain_file(filepath)
    decompress_elapsed = time.time() - t_decompress0
    if is_temp:
        print(f"  Gzip detected       : decompressed to temp file in {decompress_elapsed:.2f}s "
              f"(this step is single-threaded; splitting itself only works on the "
              f"decompressed bytes, not the compressed stream)")

    fmt = sniff_file(actual_path)
    record_source_seen(source_name, filepath, fmt)
    print(f"  Detected format     : {fmt}")

    header_fields = None
    if fmt == "csv":
        with open(actual_path, "r", encoding="utf-8", errors="replace") as f:
            header_line = f.readline()
        import csv as _csv
        import io as _io
        header_fields = next(_csv.reader(_io.StringIO(header_line)))
        header_byte_len = len(header_line.encode("utf-8"))
    else:
        header_byte_len = 0

    t0 = time.time()
    chunks = find_chunk_boundaries(actual_path, num_workers)
    boundary_elapsed = time.time() - t0
    print(f"  Chunks              : {len(chunks)}  (boundary scan took {boundary_elapsed:.2f}s)")

    if fmt == "csv" and chunks:
        # chunk 0 currently starts at byte 0, which includes the header
        # line itself -- skip past it so process_chunk_csv only ever
        # sees data rows, uniformly across every chunk.
        chunks[0] = dict(chunks[0])
        chunks[0]["start_byte"] += header_byte_len
        chunks[0]["start_line"] = 2

    shard_root = os.path.join(BIGFILE_DIR, source_name)
    if os.path.exists(shard_root):
        shutil.rmtree(shard_root)

    worker_args = []
    for i, chunk in enumerate(chunks):
        shard_dir = os.path.join(shard_root, f"chunk_{i:03d}")
        worker_args.append((
            actual_path, fmt, chunk, i, source_name,
            header_fields, filepath, shard_dir,
        ))

    t_process0 = time.time()
    with mp.Pool(processes=min(num_workers, len(chunks))) as pool:
        results = pool.map(_worker, worker_args)
    process_elapsed = time.time() - t_process0

    results.sort(key=lambda r: r["chunk_idx"])
    total_events = sum(r["count"] for r in results)
    sum_worker_time = sum(r["elapsed"] for r in results)

    print("\n" + "-" * 78)
    for r in results:
        print(f"  chunk {r['chunk_idx']:03d}  events={r['count']:8,d}  worker_time={r['elapsed']:.2f}s")

    # ---- merge shards back into single output files ----
    merged_dir = os.path.join(shard_root, "_merged")
    os.makedirs(merged_dir, exist_ok=True)
    jsonl_paths = [os.path.join(r["shard_dir"], "events.jsonl") for r in results]
    ndjson_paths = [os.path.join(r["shard_dir"], "elastic_bulk.ndjson") for r in results]
    docs_paths = [os.path.join(r["shard_dir"], "elastic_docs.ndjson") for r in results]
    parquet_paths = [os.path.join(r["shard_dir"], "events.parquet") for r in results]

    t_merge0 = time.time()
    _merge_line_files(jsonl_paths, os.path.join(merged_dir, "all_events.jsonl"))
    _merge_line_files(ndjson_paths, os.path.join(merged_dir, "elastic_bulk.ndjson"))
    _merge_line_files(docs_paths, os.path.join(merged_dir, "elastic_docs.ndjson"))
    _merge_parquet(parquet_paths, os.path.join(merged_dir, "events.parquet"))
    write_elasticsearch_mapping(os.path.join(merged_dir, "elasticsearch_mapping.json"))

    merged_agg = DashboardAggregator()
    merged_agg.total = total_events
    for r in results:
        merged_agg.action_counts.update(r["action_counts"])
        merged_agg.format_counts.update(r["format_counts"])
        merged_agg.vendor_counts.update(r["vendor_counts"])
        merged_agg.src_ip_counts.update(r["src_ip_counts"])
        merged_agg.conf_buckets.update(r["conf_buckets"])
        for row in r["sample_rows"]:
            if len(merged_agg.sample_rows) < merged_agg.sample_size:
                merged_agg.sample_rows.append(row)
    render_dashboard(merged_agg, os.path.join(merged_dir, "dashboard.html"),
                      title=f"ULPF - {source_name} (chunked, {len(chunks)} workers)")
    merge_elapsed = time.time() - t_merge0

    if not keep_shards:
        for r in results:
            shutil.rmtree(r["shard_dir"], ignore_errors=True)

    if is_temp:
        os.unlink(actual_path)

    wall_total = decompress_elapsed + boundary_elapsed + process_elapsed + merge_elapsed

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    print(f"  Total events            : {total_events:,}")
    print(f"  Workers                 : {min(num_workers, len(chunks))}")
    print(f"  Decompress step         : {decompress_elapsed:.2f}s")
    print(f"  Boundary-scan step      : {boundary_elapsed:.2f}s")
    print(f"  Parallel processing     : {process_elapsed:.2f}s wall  "
          f"(sum of worker time: {sum_worker_time:.2f}s -> "
          f"{sum_worker_time / process_elapsed:.2f}x speedup)")
    print(f"  Merge step              : {merge_elapsed:.2f}s")
    print(f"  End-to-end wall time    : {wall_total:.2f}s")
    print(f"  Throughput              : {total_events / wall_total:,.0f} events/sec")
    print(f"\n  Merged output written to: {merged_dir}/")
    return {
        "total_events": total_events, "wall_total": wall_total,
        "process_elapsed": process_elapsed, "sum_worker_time": sum_worker_time,
        "merged_dir": merged_dir,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python3 run_demo_bigfile.py <path-to-file> [num_workers]")
        sys.exit(1)
    path = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else None
    process_large_file(path, num_workers=n)
