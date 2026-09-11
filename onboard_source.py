"""
Requirement e: plug-and-play onboarding.

Run this against a sample from a brand-new log source before wiring it
into the real pipeline. It tells you exactly how much work (if any) is
needed to support it:

    python3 onboard_source.py --sample /path/to/new_source_sample.log --name paloalto-fw1

Three possible outcomes:
  1. Self-describing shape (json/csv/kv/cef) -> ready immediately,
     zero code written.
  2. Coded-syslog shape with an unrecognized vendor prefix -> scaffolds
     a starter codebook JSON with every message code it found, so a
     human only has to fill in regex templates, not build a parser.
  3. Totally unrecognized shape -> tells you it will run through the
     statistical (Drain) fallback automatically, and estimates how many
     sample lines you should feed it for the clustering to stabilize.
"""
import argparse
import json
import os
import re
from collections import Counter

from sniffer import sniff_file, CODED_SYSLOG_PATTERN
from registry import record_source_seen
from parsers.coded_syslog import _PREFIX_TO_VENDOR, _CODEBOOKS

_CODEBOOK_DIR = os.path.join(os.path.dirname(__file__), "codebooks")


def scaffold_codebook(sample_path, prefix):
    codes = Counter()
    example_lines = {}
    with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = re.search(rf"%{prefix}-\d-(\d+):", line)
            if m:
                code = m.group(1)
                codes[code] += 1
                example_lines.setdefault(code, line.strip())

    template = {
        "vendor": prefix.lower(),
        "product": "UNKNOWN - fill in",
        "messages": [
            {
                "code": code,
                "description": "TODO: describe this message",
                "action": "other",
                "event_type": "other",
                "regex": "TODO: write a regex with named groups, e.g. (?P<src_ip>[\\d.]+)",
                "_example_line": example_lines[code],
                "_seen_count": count,
            }
            for code, count in codes.most_common()
        ],
    }

    out_path = os.path.join(_CODEBOOK_DIR, f"{prefix.lower()}_TEMPLATE.json")
    with open(out_path, "w") as f:
        json.dump(template, f, indent=2)
    return out_path, len(codes)


def onboard(sample_path, source_name):
    detected = sniff_file(sample_path)
    print(f"Sniffed format: {detected}")

    if detected in ("json", "csv", "kv_syslog", "cef", "leef", "syslog5424"):
        record_source_seen(source_name, sample_path, detected)
        print(f"'{source_name}' is a self-describing '{detected}' shape.")
        print("No new code needed -- the existing extractor handles it.")
        print("Ready to run through pipeline.process_file() immediately.")
        return

    if detected == "coded_syslog":
        with open(sample_path, "r", encoding="utf-8", errors="replace") as f:
            first_match = None
            for line in f:
                m = CODED_SYSLOG_PATTERN.search(line)
                if m:
                    first_match = m.group(0)
                    break
        prefix = None
        if first_match:
            prefix_match = re.match(r"%([A-Za-z0-9_]+)-", first_match)
            prefix = prefix_match.group(1) if prefix_match else None

        existing_vendor = _PREFIX_TO_VENDOR.get(prefix)
        if existing_vendor and existing_vendor in _CODEBOOKS:
            record_source_seen(source_name, sample_path, detected)
            print(f"'{source_name}' uses message-code prefix '%{prefix}', "
                  f"already covered by the '{existing_vendor}' codebook.")
            print("No new code needed.")
            return

        print(f"'{source_name}' is a coded-syslog shape with prefix "
              f"'%{prefix}', not yet in any codebook.")
        out_path, n_codes = scaffold_codebook(sample_path, prefix)
        record_source_seen(source_name, sample_path, detected)
        print(f"Scaffolded a starter codebook with {n_codes} message code(s) "
              f"found in the sample:")
        print(f"  {out_path}")
        print("Fill in the 'regex' and 'action'/'event_type' fields for each "
              "code (an example line is included per code to work from), "
              "then rename the file to drop '_TEMPLATE'.")
        print("This is config, not new Python -- no parser code required.")
        return

    # totally unrecognized shape
    record_source_seen(source_name, sample_path, detected)
    with open(sample_path) as f:
        n_lines = sum(1 for _ in f)
    print(f"'{source_name}' doesn't match any known shape.")
    print("It will be handled automatically by the statistical (Drain) "
          "fallback -- no action required to start ingesting it.")
    print(f"Sample has {n_lines} lines. Drain's template clustering "
          "improves with volume; for stable field extraction, feeding it "
          "at least a few hundred lines of real traffic is recommended "
          "before trusting extracted fields at anything above 'low' "
          "confidence.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Onboard a new log source")
    parser.add_argument("--sample", required=True, help="Path to a sample log file")
    parser.add_argument("--name", required=True, help="Human-readable source name")
    args = parser.parse_args()
    onboard(args.sample, args.name)
