"""
CSV: the header row IS the schema. No mapping to write by hand, ever.
"""
import csv

from sniffer import open_maybe_compressed


def parse_file(filepath):
    with open_maybe_compressed(filepath) as f:
        reader = csv.DictReader(f)
        for row in reader:
            yield row
