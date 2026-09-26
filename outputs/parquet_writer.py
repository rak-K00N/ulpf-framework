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

# Explicit, fixed schema -- deliberately NOT inferred per-batch.
# pa.Table.from_pylist() infers each column's type from the values it
# actually sees in that batch: a batch where every "host" happens to be
# None infers as a `null` type, while a later batch with real hostnames
# infers `string` -- two different schemas from the same logical column,
# which crashes ParquetWriter.write_table() the moment batch 2 doesn't
# match batch 1 (this is exactly what streaming batches hit in practice,
# since fields like host/process/pid are only populated for a subset of
# formats). Fixing the schema up front, matching schema.NORMALIZED_FIELDS,
# guarantees every batch casts to the identical schema regardless of how
# many nulls it happens to contain.
PARQUET_SCHEMA = pa.schema([
    ("event_id", pa.string()),
    ("timestamp", pa.string()),
    ("vendor", pa.string()),
    ("source_format", pa.string()),
    ("event_type", pa.string()),
    ("action", pa.string()),
    ("severity", pa.string()),
    ("src_ip", pa.string()),
    ("src_port", pa.int64()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int64()),
    ("protocol", pa.string()),
    ("bytes_sent", pa.int64()),
    ("bytes_received", pa.int64()),
    ("packets", pa.int64()),
    ("user", pa.string()),
    ("host", pa.string()),
    ("process", pa.string()),
    ("pid", pa.string()),
    ("message", pa.string()),
    ("confidence", pa.float64()),
    ("raw", pa.string()),
    ("lineage_event_id", pa.string()),
    ("lineage_source_path", pa.string()),
    ("lineage_source_name", pa.string()),
    ("lineage_line_number", pa.int64()),
    ("lineage_ingested_at", pa.string()),
])


def _flatten(event):
    flat = {k: v for k, v in event.items() if k != "lineage"}
    lineage = event.get("lineage") or {}
    for k, v in lineage.items():
        flat[f"lineage_{k}"] = v
    return flat


def write_parquet(events, out_path, batch_size=10_000):
    """
    Streams events into Parquet in fixed-size batches instead of building
    one giant pa.Table in memory. The old version did
    `rows = [_flatten(e) for e in events]` -- fine for the 54K-line demo
    corpus, but at GB-scale input (millions of events) that list is the
    actual memory ceiling, not the parsing engine (which already streams).
    Memory here stays O(batch_size) regardless of total event count,
    because schema.py's NORMALIZED_FIELDS is a fixed set of columns for
    every event, so every batch's schema is guaranteed identical and a
    single ParquetWriter can be reused across all of them.
    """
    writer = pq.ParquetWriter(out_path, PARQUET_SCHEMA, compression="snappy")
    batch = []
    count = 0
    try:
        for event in events:
            batch.append(_flatten(event))
            if len(batch) >= batch_size:
                writer.write_table(pa.Table.from_pylist(batch, schema=PARQUET_SCHEMA))
                count += len(batch)
                batch = []
        if batch:
            writer.write_table(pa.Table.from_pylist(batch, schema=PARQUET_SCHEMA))
            count += len(batch)
    finally:
        writer.close()
    return count
