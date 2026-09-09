"""
Each line is a self-describing JSON object. Zero guessing required --
whatever keys are present ARE the schema. Works for any JSON-emitting
source (VPC flow logs, container logs, app logs), not just one cloud.
"""
import json


def parse_line(line):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None
