"""
Single-huge-file chunked parallel processing.

run_demo_parallel.py already parallelizes across *many separate source
files* safely, because each Drain miner is keyed per source and never
shares state. This module handles the other GB-scale case: input
arriving as *one* multi-gigabyte file, where there's nothing to split
across processes unless we split the file itself.

Approach: divide the file into num_workers roughly-equal byte ranges,
snap each boundary forward to the next newline so no line is ever cut
in half, and hand each (start_byte, end_byte) range to its own worker
process. This is safe because every event's lineage (source_path +
line_number, see lineage.py) is computed independently per line --
chunks never need to agree on shared state, and it doesn't matter that
chunk 3 might finish before chunk 1.

Two shapes need special handling because they aren't purely
line-independent:
  - gzip (.gz): you cannot seek to an arbitrary byte offset in a
    compressed stream and start decompressing from there -- deflate
    state depends on everything before it. Compressed files are
    decompressed to a temp file first (one linear pass), then chunked
    normally. Flagged clearly in the summary output, since that
    decompression pass is itself single-threaded.
  - csv: the header row is the schema (see parsers/csv_parser.py's own
    docstring). Every chunk after the first needs that header handed to
    it explicitly, since only chunk 0 actually contains the header line
    in its byte range.

Known limitation (documented, not hidden): each chunk gets its own
Drain template miner instance for the 'unknown' fallback path, seeded
from only that chunk's slice of the data, rather than one miner seeing
the whole file. Template convergence is therefore per-chunk rather than
global -- functionally correct (every line still gets parsed and
normalized), but a chunk that happens to get an unlucky sample of a
rare template may converge slightly slower than a single-process run
would. This is a real, measured trade of a small amount of clustering
quality for the throughput of true parallelism; merging Drain
vocabularies across processes afterward is possible future work, not
implemented here.
"""
import csv
import gzip
import io
import os
import tempfile

import pyarrow as pa
import pyarrow.parquet as pq

from lineage import make_lineage
from normalizer import normalize_csv, finalize
from outputs.parquet_writer import PARQUET_SCHEMA, _flatten
from pipeline import DrainFallbackParser, process_line
from sniffer import sniff_file
from registry import record_source_seen


def materialize_plain_file(filepath):
    """Chunked byte-offset seeking requires a real, seekable, uncompressed
    file. Gzip's compressed byte offsets don't correspond to decompressed
    line boundaries at all, so a .gz input is decompressed once, up front,
    to a temp file -- after that everything below works identically to a
    plain file. Returns (path_to_use, is_temp)."""
    with open(filepath, "rb") as probe:
        is_gzip = probe.read(2) == b"\x1f\x8b"
    if not is_gzip:
        return filepath, False

    tmp = tempfile.NamedTemporaryFile(prefix="ulpf_decompressed_", suffix=".log", delete=False)
    with gzip.open(filepath, "rb") as src:
        while True:
            block = src.read(16 * 1024 * 1024)
            if not block:
                break
            tmp.write(block)
    tmp.close()
    return tmp.name, True


def find_chunk_boundaries(filepath, num_chunks):
    """
    Single linear pass over the file (pure byte/newline counting -- no
    regex, no parsing, no Drain) to find num_chunks line-aligned byte
    ranges and the true global starting line number of each one. This
    pass is comparatively cheap: the parsing work each chunk does
    afterward (format detection per line, regex extraction, Drain
    clustering) is the expensive part by a wide margin, so paying for one
    fast sequential read here to enable true parallelism on the expensive
    part is a good trade.

    Returns a list of dicts: {start_byte, end_byte, start_line}, in file
    order, covering the whole file exactly once.
    """
    size = os.path.getsize(filepath)
    if size == 0:
        return [{"start_byte": 0, "end_byte": 0, "start_line": 1}]
    num_chunks = max(1, num_chunks)
    if num_chunks == 1:
        return [{"start_byte": 0, "end_byte": size, "start_line": 1}]

    target_offsets = sorted(set(round(size * i / num_chunks) for i in range(1, num_chunks)))

    split_points = []  # (byte_offset_of_next_chunk_start, line_number_of_next_chunk_start)
    with open(filepath, "rb") as f:
        pos = 0
        line_no = 0
        next_target_idx = 0
        for raw_line in f:
            line_no += 1
            pos += len(raw_line)
            while next_target_idx < len(target_offsets) and pos >= target_offsets[next_target_idx]:
                split_points.append((pos, line_no + 1))
                next_target_idx += 1
        end_pos = pos

    # De-duplicate: on a short file, several targets can land on the same
    # actual newline -- collapse those into a single real boundary so we
    # never emit a zero-length chunk.
    seen_bytes = set()
    deduped = []
    for byte_off, line_no in split_points:
        if byte_off not in seen_bytes and byte_off < end_pos:
            seen_bytes.add(byte_off)
            deduped.append((byte_off, line_no))

    starts = [(0, 1)] + deduped
    chunks = []
    for i, (start_byte, start_line) in enumerate(starts):
        end_byte = starts[i + 1][0] if i + 1 < len(starts) else end_pos
        if end_byte > start_byte:
            chunks.append({"start_byte": start_byte, "end_byte": end_byte, "start_line": start_line})
    return chunks


def _read_lines_in_range(filepath, start_byte, end_byte):
    """Yields decoded, newline-stripped lines strictly within [start_byte,
    end_byte). Reads in binary mode and decodes per-line so the byte
    offsets computed by find_chunk_boundaries stay authoritative --
    Python text-mode files can translate/buffer newlines in ways that
    make raw byte-offset seeking unreliable."""
    with open(filepath, "rb") as f:
        f.seek(start_byte)
        pos = start_byte
        while pos < end_byte:
            raw = f.readline()
            if not raw:
                break
            pos += len(raw)
            line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if line.strip():
                yield line


def process_chunk_generic(filepath, fmt, chunk, source_name, source_path_for_lineage):
    """Non-CSV formats: reuse pipeline.process_line directly, per line,
    with a Drain miner private to this chunk (see module docstring on
    why persistence is intentionally disabled here)."""
    drain = DrainFallbackParser(persistence_path=None) if fmt == "unknown" else None
    line_no = chunk["start_line"]
    for line in _read_lines_in_range(filepath, chunk["start_byte"], chunk["end_byte"]):
        lineage = make_lineage(source_path_for_lineage, line_no, line, source_name)
        event = process_line(line, fmt_hint=fmt, lineage=lineage, drain=drain)
        yield event
        line_no += 1


def process_chunk_csv(filepath, chunk, header_fields, source_name, source_path_for_lineage):
    """CSV chunks can't use process_line (there's no per-line CSV shape
    to sniff -- the header, read once up front, IS the schema). Each
    chunk after the first starts directly at data rows, so csv.DictReader
    is given the shared header explicitly instead of reading one from
    the chunk itself."""
    line_no = chunk["start_line"]
    lines = list(_read_lines_in_range(filepath, chunk["start_byte"], chunk["end_byte"]))
    reader = csv.DictReader(io.StringIO("\n".join(lines)), fieldnames=header_fields)
    for row, raw_line in zip(reader, lines):
        lineage = make_lineage(source_path_for_lineage, line_no, raw_line, source_name)
        yield finalize(normalize_csv(row, raw_line, lineage))
        line_no += 1
