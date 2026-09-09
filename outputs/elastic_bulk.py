"""
Requirement g: efficient SIEM integration.

Writes normalized events in the exact NDJSON shape Elasticsearch's/
OpenSearch's _bulk API expects (an action line, then a doc line, per
event) -- the format nearly every SIEM's ingest pipeline is built
around. This file is generated entirely offline; nothing here requires
a running Elasticsearch instance, network access, or credentials.
Ship the .ndjson file into the air-gapped boundary's SIEM however your
environment allows (sneakernet, one-way diode, batch import job).
"""
import json


def write_bulk_ndjson(events, out_path, index_name="ulpf-events"):
    """
    Each event becomes two lines:
        {"index": {"_index": "...", "_id": "<event_id>"}}
        {...the normalized event...}
    Using event_id as the Elasticsearch document _id means re-ingesting
    the same file twice overwrites rather than duplicates -- idempotent
    ingestion, which matters a lot for replay/recovery scenarios.
    """
    count = 0
    with open(out_path, "w") as f:
        for event in events:
            action = {"index": {"_index": index_name, "_id": event.get("event_id")}}
            f.write(json.dumps(action) + "\n")
            f.write(json.dumps(event) + "\n")
            count += 1
    return count
