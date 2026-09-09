"""
Handles syslog lines where the useful fields are embedded in a free-text
message tied to a stable vendor message code, e.g.:
    <164>Aug 31 2026 09:18:44 ASA-FW01 : %ASA-4-106023: Deny tcp src ...

Nothing here is hardcoded per-vendor in Python. Every code -> regex
mapping lives in codebooks/*.json. Adding support for a new coded-syslog
vendor (Palo Alto, Juniper, whatever) means adding a JSON file, not
writing a new parser.
"""
import glob
import json
import os
import re

HEADER_PATTERN = re.compile(
    r"^<(?P<pri>\d+)>(?P<timestamp>\w+\s+\d+\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<hostname>\S+)\s*:?\s*%(?P<prefix>[A-Za-z0-9_]+)-(?P<severity>\d)-(?P<code>\d+):\s*"
    r"(?P<message>.*)$"
)

_CODEBOOK_DIR = os.path.join(os.path.dirname(__file__), "..", "codebooks")


def _load_codebooks():
    """Loads every codebook JSON and indexes it by message-code prefix."""
    codebooks = {}
    for path in glob.glob(os.path.join(_CODEBOOK_DIR, "*.json")):
        with open(path, "r") as f:
            data = json.load(f)
        by_code = {m["code"]: m for m in data["messages"]}
        codebooks[data["vendor"]] = {
            "vendor": data["vendor"],
            "product": data.get("product"),
            "by_code": by_code,
        }
    return codebooks


_CODEBOOKS = _load_codebooks()

# maps the %PREFIX (e.g. "ASA") seen in the log line to a codebook vendor
_PREFIX_TO_VENDOR = {"ASA": "cisco"}


def parse_line(line):
    header_match = HEADER_PATTERN.match(line.strip())
    if not header_match:
        return None

    fields = header_match.groupdict()
    prefix = fields.pop("prefix")
    code = fields["code"]
    vendor = _PREFIX_TO_VENDOR.get(prefix)
    codebook = _CODEBOOKS.get(vendor)

    if not codebook or code not in codebook["by_code"]:
        # Header parsed fine, but we've never seen this specific message
        # code before -- return what we know with low confidence instead
        # of silently dropping the event.
        fields["vendor"] = vendor or prefix.lower()
        fields["matched_code"] = False
        fields["action"] = "other"
        fields["event_type"] = "unknown_code"
        return fields

    code_entry = codebook["by_code"][code]
    body_match = re.search(code_entry["regex"], fields["message"])

    fields["vendor"] = vendor
    fields["matched_code"] = True
    fields["action"] = code_entry["action"]
    fields["event_type"] = code_entry["event_type"]
    fields["description"] = code_entry["description"]

    if body_match:
        fields.update(body_match.groupdict())
        fields["body_matched"] = True
    else:
        # code recognized, but the message body didn't fit the expected
        # template exactly (vendor drift). Still return the header info.
        fields["body_matched"] = False

    return fields
