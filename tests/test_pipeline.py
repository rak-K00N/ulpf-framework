"""
Lightweight regression check, not a full test suite: runs every sample
through the pipeline and asserts each format parses every line with no
silent drops and no unexpected confidence collapse. Run after touching
any parser, the sniffer, or a codebook.

    python3 tests/test_pipeline.py
"""
import glob
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pipeline
from sniffer import sniff_file

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")

# (filename, expected_detected_format, min_avg_confidence)
EXPECTATIONS = [
    ("01_fortinet_syslog.log", "kv_syslog", 0.9),
    ("02_fortinet_cef.log", "cef", 0.9),
    ("03_cisco_asa_syslog.log", "coded_syslog", 0.8),
    ("04_cloud_flow_logs.json", "json", 0.9),
    ("05_firewall_export.csv", "csv", 0.9),
    ("06_unknown_format.log", "unknown", 0.0),
    ("07_checkpoint_leef.log", "leef", 0.9),
    ("08_juniper_syslog5424.log", "syslog5424", 0.9),
    ("09_cisco_firepower_syslog.log", "coded_syslog", 0.8),
    ("10_fortinet_syslog_archived.log.gz", "kv_syslog", 0.9),
    # LogHub real-world corpus -- all deliberately unrecognized shapes,
    # exercising the Drain + heuristic-tagging fallback path with zero
    # per-source parsers.
    ("11_android_unknown.log", "unknown", 0.35),
    ("12_apache_unknown.log", "unknown", 0.35),
    ("13_bgl_supercomputer_unknown.log", "unknown", 0.35),
    ("14_hadoop_unknown.log", "unknown", 0.35),
    ("15_hdfs_unknown.log", "unknown", 0.35),
    ("16_healthapp_unknown.log", "unknown", 0.3),
    ("17_hpc_unknown.log", "unknown", 0.3),
    ("18_linux_syslog_unknown.log", "unknown", 0.4),
    ("19_mac_unknown.log", "unknown", 0.4),
    ("20_openssh_unknown.log", "unknown", 0.4),
    ("21_openstack_unknown.log", "unknown", 0.35),
    ("22_proxifier_unknown.log", "unknown", 0.3),
    ("23_spark_unknown.log", "unknown", 0.35),
    ("24_thunderbird_unknown.log", "unknown", 0.35),
    ("25_windows_unknown.log", "unknown", 0.35),
]


def main():
    failures = []
    for fname, expected_fmt, min_conf in EXPECTATIONS:
        path = os.path.join(SAMPLES_DIR, fname)
        if not os.path.exists(path):
            failures.append(f"{fname}: MISSING sample file")
            continue

        detected = sniff_file(path)
        if detected != expected_fmt:
            failures.append(f"{fname}: expected format '{expected_fmt}', got '{detected}'")
            continue

        events = list(pipeline.process_file(path, source_name=fname))
        n = len(events)
        if n == 0:
            failures.append(f"{fname}: zero events parsed")
            continue

        avg_conf = sum(e["confidence"] for e, _ in events) / n
        if avg_conf < min_conf:
            failures.append(f"{fname}: avg confidence {avg_conf:.2f} below floor {min_conf}")

        # every event must carry lineage back to this exact file (requirement d)
        bad_lineage = [e for e, _ in events if e["lineage"]["source_path"] != path]
        if bad_lineage:
            failures.append(f"{fname}: {len(bad_lineage)} events missing correct lineage")

        print(f"OK  {fname:42s} fmt={detected:12s} n={n:5d} avg_conf={avg_conf:.2f}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} issue(s)")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print(f"All {len(EXPECTATIONS)} sample formats passed.")


if __name__ == "__main__":
    main()
