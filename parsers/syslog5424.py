"""
RFC 5424 structured syslog, the successor to the classic BSD (RFC 3164)
format used by kv_syslog. A growing set of modern perimeter devices
(F5, Juniper, newer Palo Alto builds, load balancers, VPN concentrators)
emit this instead of vendor-specific key=value text, e.g.:

    <134>1 2026-08-31T09:12:03.118Z fw2.example.com netfw 1234 ID47 \
        [firewall@32473 srcIP="10.0.0.5" dstIP="93.184.216.34" \
        srcPort="55321" dstPort="443" proto="tcp" action="accept" \
        bytesSent="2048" bytesRecv="4096"] Connection accepted

The header (PRI, VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID)
and the structured-data blocks (SD-ID plus quoted key="value" pairs) are
both published, self-describing grammar -- RFC 5424 section 6. This
parser needs no per-vendor knowledge, same philosophy as cef.py/leef.py:
parse by shape, not by vendor.
"""
import re

HEADER_PATTERN = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+(?P<hostname>\S+)\s+(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd_and_msg>.*)$"
)
SD_ELEMENT_PATTERN = re.compile(r"\[(?P<sdid>[^\s\]]+)(?P<params>(?:\s+\S+?=\"[^\"]*\")*)\s*\]")
SD_PARAM_PATTERN = re.compile(r'(\S+?)="([^"]*)"')


def _split_structured_data(sd_and_msg):
    """RFC 5424 structured data is zero or more bracketed elements right
    after MSGID, or a literal '-' if absent, followed by the free-text
    MSG. Brackets don't nest, so a simple scan from the front is
    sufficient and avoids over-matching into the message body."""
    sd_and_msg = sd_and_msg.strip()
    if sd_and_msg.startswith("-"):
        return "", sd_and_msg[1:].strip()

    if not sd_and_msg.startswith("["):
        return "", sd_and_msg

    depth = 0
    for i, ch in enumerate(sd_and_msg):
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
            if depth == 0:
                # keep consuming consecutive [..] elements
                rest = sd_and_msg[i + 1:]
                if rest.startswith(" ["):
                    continue
                return sd_and_msg[: i + 1], rest.strip()
    return sd_and_msg, ""


def parse_structured_data(sd_text):
    fields = {}
    for element in SD_ELEMENT_PATTERN.finditer(sd_text):
        for key, value in SD_PARAM_PATTERN.findall(element.group("params")):
            fields[key] = value
    return fields


def parse_line(line):
    match = HEADER_PATTERN.match(line.strip())
    if not match:
        return None

    fields = match.groupdict()
    sd_text, message = _split_structured_data(fields.pop("sd_and_msg"))

    fields.update(parse_structured_data(sd_text))
    fields["message"] = message
    fields["has_structured_data"] = bool(sd_text)
    return fields
