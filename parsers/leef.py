"""
LEEF (Log Event Extended Format) is IBM's published, versioned spec --
the LEEF equivalent of CEF, and the native output format of Check Point,
Juniper, and several other perimeter vendors when QRadar-style ingestion
is configured:

    LEEF:2.0|Vendor|Product|Version|EventID|Delimiter|ext1=val1<TAB>ext2=val2

LEEF 1.0 omits the explicit delimiter field and always uses tab. LEEF 2.0
adds a 6th header field naming the extension delimiter, which is either a
literal character or a hex escape like "x09" (tab). Like cef.py, this
parser is fully mechanical: it never needs to know which vendor sent it,
just the published header/extension grammar.
"""
import re

LEEF_HEADER_PATTERN = re.compile(
    r"LEEF:(?P<leef_version>[\d.]+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<product_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<rest>.*)$"
)
EXT_KEY_PATTERN = re.compile(r"(\w+)=")


def _resolve_delimiter(token):
    """LEEF 2.0's delimiter field is either a literal char or a hex escape
    (x09 = tab, x2c = comma, ...). LEEF 1.0 has no such field, so callers
    pass None and get the tab default."""
    if token is None or token == "":
        return "\t"
    m = re.match(r"^[xX]([0-9A-Fa-f]{2})$", token)
    if m:
        return chr(int(m.group(1), 16))
    return token


def parse_extension(extension, delimiter):
    """LEEF extension values are delimiter-separated key=value pairs. Like
    CEF, values can be empty or contain the delimiter itself only if
    escaped, but a mechanical split-on-next-key is robust enough here
    (same technique as cef.parse_extension)."""
    matches = list(EXT_KEY_PATTERN.finditer(extension))
    result = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        value = extension[start:end]
        # trim exactly one trailing delimiter, keep internal spacing
        if value.endswith(delimiter):
            value = value[: -len(delimiter)]
        result[key] = value.strip()
    return result


def parse_line(line):
    prefix, _, leef_part = line.partition("LEEF:")
    if not leef_part:
        return None
    match = LEEF_HEADER_PATTERN.search("LEEF:" + leef_part)
    if not match:
        return None

    fields = match.groupdict()
    rest = fields.pop("rest")
    version = fields["leef_version"]

    delimiter_token = None
    extension = rest
    if version.startswith("2"):
        # LEEF 2.0: next field up to the first delimiter-looking token is
        # the delimiter spec, rest is the extension.
        head, sep, tail = rest.partition("|")
        if sep and (len(head) <= 4):
            delimiter_token = head
            extension = tail
    delimiter = _resolve_delimiter(delimiter_token)

    extension_fields = parse_extension(extension, delimiter)
    fields.update(extension_fields)
    fields["syslog_prefix"] = prefix.strip()
    return fields
