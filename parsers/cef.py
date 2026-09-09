"""
CEF is a published, versioned spec:
    CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension

Often preceded by a plain syslog prefix (timestamp, hostname). This parser
is fully mechanical -- it never needs to know which vendor sent it.
"""
import re

CEF_HEADER_PATTERN = re.compile(
    r"CEF:(?P<cef_version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<product_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|(?P<extension>.*)$"
)
EXT_KEY_PATTERN = re.compile(r"(\w+)=")


def parse_extension(extension):
    """
    CEF extension values are unquoted and can contain spaces, so we can't
    just split on spaces. Instead we find every key= position and slice
    the text between consecutive keys.
    """
    matches = list(EXT_KEY_PATTERN.finditer(extension))
    result = {}
    for i, m in enumerate(matches):
        key = m.group(1)
        start = m.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(extension)
        result[key] = extension[start:end].strip()
    return result


def parse_line(line):
    prefix, _, cef_part = line.partition("CEF:")
    match = CEF_HEADER_PATTERN.search("CEF:" + cef_part)
    if not match:
        return None

    fields = match.groupdict()
    extension_fields = parse_extension(fields.pop("extension"))
    fields.update(extension_fields)
    fields["syslog_prefix"] = prefix.strip()
    return fields
