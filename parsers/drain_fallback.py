"""
Fallback for formats the sniffer can't identify. No LLM, no internet --
this is classical log-mining: Drain clusters lines by structural
similarity and automatically splits each line into a fixed "template"
part and "variable" tokens, purely from statistics over many lines.

We then run cheap shape heuristics over the variable tokens (does it look
like an IP? a port? a timestamp?) to give them rough semantic labels.
Nothing here calls out to any network service.
"""
import re

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
PORT_PATTERN = re.compile(r"^\d{1,5}$")

# drain3's own extra_delimiters option feeds these straight into re.sub()
# for parameter extraction, which breaks on regex-special characters like
# "|". Safer to normalize delimiters into whitespace ourselves, once,
# consistently, before anything touches drain3.
_DELIMITER_TRANSLATION = str.maketrans({c: " " for c in "|,:="})


def _normalize_delimiters(line):
    return line.translate(_DELIMITER_TRANSLATION)


def _guess_tag(token):
    if IP_PATTERN.match(token):
        return "ip"
    if PORT_PATTERN.match(token) and 0 < int(token) <= 65535:
        return "port_or_number"
    if re.match(r"^\d{4}-\d{2}-\d{2}", token):
        return "date"
    if re.match(r"^\d{2}:\d{2}:\d{2}$", token):
        return "time"
    return "unknown"


class DrainFallbackParser:
    """
    Wraps drain3's TemplateMiner with in-memory persistence (no files,
    no network) and adds the shape-tagging step.
    """

    def __init__(self):
        self.miner = TemplateMiner(config=TemplateMinerConfig())

    def parse_line(self, line):
        line = _normalize_delimiters(line.strip())
        result = self.miner.add_log_message(line)
        template = result["template_mined"]
        cluster_id = result["cluster_id"]

        params = self.miner.extract_parameters(template, line, exact_matching=False) or []
        variables = [p.value for p in params]
        tagged = [{"value": v, "guessed_type": _guess_tag(v)} for v in variables]

        return {
            "template": template,
            "cluster_id": cluster_id,
            "variables": tagged,
            "cluster_size": result.get("cluster_size"),
        }
