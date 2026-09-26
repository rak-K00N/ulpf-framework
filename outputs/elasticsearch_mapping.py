"""
Elasticsearch's dynamic mapping *guesses* field types from whichever
document it sees first for each field, then locks that guess in for the
whole index -- get unlucky (e.g. the first src_ip happens to arrive as
an empty string) and every later document with a real IP either gets
coerced oddly or rejected outright. For a "SIEM-ready output" story,
leaving that to chance is a real gap: this is the explicit mapping that
removes the guesswork, with the field types that actually make Kibana's
visualization/dashboard tooling work well:

  - timestamp / @timestamp -> `date`: required for any date histogram,
    time-series panel, or "last 24 hours" filter. Elasticsearch's
    default dynamic date detection format (strict_date_optional_time)
    happens to accept the exact ISO-8601 shape timestamp_utils.py now
    produces, so this would likely work even without an explicit
    mapping -- but explicit is correct, not lucky.
  - src_ip / dst_ip -> `ip`: enables CIDR-range queries ("10.0.0.0/8")
    and Kibana's built-in Maps/IP visualizations. A generic `keyword`
    would only support exact-match lookups.
  - action/vendor/source_format/etc -> `keyword`: exact-match and
    aggregatable (needed for any terms aggregation / bar chart /
    Kibana "top values" panel). `text` alone is analyzed and full-text
    searchable but NOT aggregatable -- a dashboard trying to bucket by
    "action" against a `text` field silently fails to group correctly.
  - message/raw -> `text`: the one place free-text search is actually
    wanted.
  - confidence -> `float`; ports/bytes/packets/line_number -> `integer`.
"""
import json

MAPPING = {
    "mappings": {
        "properties": {
            "event_id": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "@timestamp": {"type": "date"},
            "vendor": {"type": "keyword"},
            "source_format": {"type": "keyword"},
            "event_type": {"type": "keyword"},
            "action": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "src_ip": {"type": "ip"},
            "src_port": {"type": "integer"},
            "dst_ip": {"type": "ip"},
            "dst_port": {"type": "integer"},
            "protocol": {"type": "keyword"},
            "bytes_sent": {"type": "integer"},
            "bytes_received": {"type": "integer"},
            "packets": {"type": "integer"},
            "user": {"type": "keyword"},
            "host": {"type": "keyword"},
            "process": {"type": "keyword"},
            "pid": {"type": "keyword"},
            "message": {"type": "text"},
            "confidence": {"type": "float"},
            "raw": {"type": "text"},
            "lineage": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "source_path": {"type": "keyword"},
                    "source_name": {"type": "keyword"},
                    "line_number": {"type": "integer"},
                    "ingested_at": {"type": "date"},
                }
            },
        }
    }
}


def write_elasticsearch_mapping(out_path):
    with open(out_path, "w") as f:
        json.dump(MAPPING, f, indent=2)
    return out_path
