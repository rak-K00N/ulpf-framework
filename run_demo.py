"""
Runs the full pipeline against every file in samples/ and demonstrates
all four of: traceability (d), plug-and-play onboarding (e), unified
visibility (f), and SIEM/data-lake integration (g).

No network calls anywhere in this file or anything it imports.
"""
import glob
import json
import os

from pipeline import process_file
from sniffer import sniff_file
import registry
from dashboard import generate_dashboard
from outputs.elastic_bulk import write_bulk_ndjson
from outputs.parquet_writer import write_parquet

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output")


def confidence_bucket(c):
    if c >= 0.8:
        return "high"
    if c >= 0.4:
        return "medium"
    return "low"


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    jsonl_path = os.path.join(OUTPUT_DIR, "all_events.jsonl")

    files = sorted(glob.glob(os.path.join(SAMPLES_DIR, "*")))
    overall_stats = {"total": 0, "high": 0, "medium": 0, "low": 0}
    per_file_summaries = []
    all_events = []

    with open(jsonl_path, "w") as out_f:
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
                out_f.write(json.dumps(event) + "\n")
                all_events.append(event)

            avg_conf = (conf_sum / count) if count else 0.0
            per_file_summaries.append({
                "file": fname, "detected_format": detected,
                "lines_processed": count, "avg_confidence": round(avg_conf, 2),
                "confidence_buckets": buckets, "example_event": example_event,
            })

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
    print("OVERALL")
    print("=" * 78)
    total = overall_stats["total"]
    for bucket in ("high", "medium", "low"):
        n = overall_stats[bucket]
        pct = (100 * n / total) if total else 0
        print(f"  {bucket:7s} confidence     : {n:6d}  ({pct:.1f}%)")

    # ---- (f) unified visibility dashboard ----
    dashboard_path = os.path.join(OUTPUT_DIR, "dashboard.html")
    generate_dashboard(all_events, dashboard_path)
    print(f"\n(f) Unified visibility dashboard written to: {dashboard_path}")
    print("    Open it directly in any browser -- no server needed.")

    # ---- (g) SIEM / data lake output adapters ----
    bulk_path = os.path.join(OUTPUT_DIR, "elastic_bulk.ndjson")
    n_bulk = write_bulk_ndjson(all_events, bulk_path)
    print(f"\n(g) SIEM-ready Elasticsearch bulk file written: {bulk_path} "
          f"({n_bulk} events)")

    parquet_path = os.path.join(OUTPUT_DIR, "events.parquet")
    n_parquet = write_parquet(all_events, parquet_path)
    print(f"(g) Data-lake-ready Parquet file written: {parquet_path} "
          f"({n_parquet} events)")

    print(f"\n  Full JSONL output also available at: {jsonl_path}")


if __name__ == "__main__":
    main()
