"""
CSV: the header row IS the schema. No mapping to write by hand, ever.
"""
import csv


def parse_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row
