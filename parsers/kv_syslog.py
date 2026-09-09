"""
Generic extractor for space-separated key=value syslog lines, e.g.:
    date=2026-08-31 time=09:12:03 srcip=192.168.1.10 action="deny"

This is NOT Fortinet-specific. Any vendor emitting this shape works with
zero changes -- the field names come straight from the log line itself.
"""
import re

KV_PATTERN = re.compile(r'(\w+)=("[^"]*"|\S+)')


def parse_line(line):
    fields = {}
    for key, value in KV_PATTERN.findall(line):
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        fields[key] = value
    return fields
