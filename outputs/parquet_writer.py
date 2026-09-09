"""
Requirement g: efficient Data Lake integration.

Writes normalized events as Parquet -- the columnar format nearly every
data lake (S3 + Athena, Spark, Delta Lake, Snowflake external tables)
reads natively. Columnar storage also means analytics queries over
billions of events only scan the columns they need, which is the whole
reason data lakes use it over row-oriented JSON at scale.

The 'lineage' field is a nested dict, so it gets flattened into its own
columns (lineage_event_id, lineage_source_path, etc.) rather than stored
as an opaque blob -- keeps it queryable in tools that don't handle
nested Parquet structs well.
"""
import pyarrow as pa
import pyarrow.parquet as pq


def _flatten(event):
    flat = {k: v for k, v in event.items() if k != "lineage"}
    lineage = event.get("lineage") or {}
    for k, v in lineage.items():
        flat[f"lineage_{k}"] = v
    return flat


def write_parquet(events, out_path):
    rows = [_flatten(e) for e in events]
    if not rows:
        return 0
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, out_path, compression="snappy")
    return len(rows)
