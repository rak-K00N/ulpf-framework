"""
Fallback for formats the sniffer can't identify (flow-chart box 6: Template
Mining). No LLM, no internet -- this is classical log-mining: Drain
clusters lines by structural similarity and automatically splits each
line into a fixed "template" part and "variable" tokens, purely from
statistics over many lines.

We then run cheap shape heuristics over each variable token (does it
look like an IP? a port? a path? a UUID?) to give it a rough semantic
label -- this is the token-level half of Heuristic Field-Type Tagging;
the line-level half (timestamp/severity/host/process) lives in
generic_profiler.py and runs on the untouched raw line. Nothing here
calls out to any network service.
"""
import re

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
IP_PORT_PATTERN = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$")
IP_PORT_ARROW_PATTERN = re.compile(
    r"^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:->|>| to )"
    r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$"
)
IPV6_PATTERN = re.compile(r"^[0-9a-fA-F:]{2,}:[0-9a-fA-F:]*$")
MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$")
HEX_PATTERN = re.compile(r"^0x[0-9a-fA-F]+$")
UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
EMAIL_PATTERN = re.compile(r"^[\w.\-]+@[\w.\-]+\.\w+$")
URL_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://\S+$")
PATH_PATTERN = re.compile(r"^(/[\w.\-]+)+/?$|^[A-Za-z]:\\[\w.\\\-]+$")
PORT_PATTERN = re.compile(r"^\d{1,5}$")
DATE_PATTERN = re.compile(r"^\d{4}[-.]\d{2}[-.]\d{2}")
TIME_PATTERN = re.compile(r"^\d{2}:\d{2}:\d{2}([.,]\d+)?$")

# Only "|" and "," are normalized to whitespace before Drain sees a line.
# Both are common field separators in pipe/CSV-flavored unknown formats
# and Drain's default tokenizer only splits on whitespace, so leaving
# them glued to their neighbors would collapse an entire delimited line
# into one opaque token. ":" and "=" are deliberately left untouched --
# timestamps ("15:16:01"), IPv6, Windows paths ("C:\...") and key=value
# fragments all depend on them, and none of those need Drain-level
# splitting to cluster correctly (a whole "uid=0" token still varies
# consistently across lines, which is all Drain needs). Real k=v
# fragments are recovered separately and losslessly by normalizer.py
# reusing the kv_syslog regex extractor directly on the raw line.
_DELIMITER_TRANSLATION = str.maketrans({c: " " for c in "|,"})


def _normalize_delimiters(line):
    return line.translate(_DELIMITER_TRANSLATION)


def _guess_tag(token):
    if not token:
        return "unknown"
    if IP_PORT_ARROW_PATTERN.match(token):
        return "ip_port_flow"
    if IP_PORT_PATTERN.match(token):
        return "ip_port"
    if IP_PATTERN.match(token):
        return "ip"
    if MAC_PATTERN.match(token):
        return "mac"
    if UUID_PATTERN.match(token):
        return "uuid"
    if EMAIL_PATTERN.match(token):
        return "email"
    if URL_PATTERN.match(token):
        return "url"
    if PATH_PATTERN.match(token):
        return "path"
    if HEX_PATTERN.match(token):
        return "hex"
    if DATE_PATTERN.match(token):
        return "date"
    if TIME_PATTERN.match(token):
        return "time"
    if IPV6_PATTERN.match(token) and token.count(":") >= 2:
        return "ipv6"
    if PORT_PATTERN.match(token) and 0 < int(token) <= 65535:
        return "port_or_number"
    if token.isdigit():
        return "large_number"
    return "unknown"


def _tag_variable(token):
    """Tags one Drain-extracted variable, and for compound shapes (an
    IP:PORT pair, or a SRC:PORT->DST:PORT flow notation used by several
    routers/firewalls) also splits out the sub-fields so the normalizer
    doesn't have to re-parse the token itself."""
    guessed_type = _guess_tag(token)
    tagged = {"value": token, "guessed_type": guessed_type}
    if guessed_type == "ip_port":
        m = IP_PORT_PATTERN.match(token)
        tagged["ip"], tagged["port"] = m.group(1), m.group(2)
    elif guessed_type == "ip_port_flow":
        m = IP_PORT_ARROW_PATTERN.match(token)
        tagged["src_ip"], tagged["src_port"] = m.group(1), m.group(2)
        tagged["dst_ip"], tagged["dst_port"] = m.group(3), m.group(4)
    return tagged


class DrainFallbackParser:
    """
    Wraps drain3's TemplateMiner and adds the token-shape-tagging step.
    One instance should be dedicated per *source* (see pipeline.py) so
    that wildly different unknown formats never pollute each other's
    template clusters -- an Android logcat line and a BGL supercomputer
    line have nothing in common and shouldn't compete for the same
    cluster space. Optionally persists learned templates to disk so a
    source's template vocabulary keeps improving across runs instead of
    restarting cold every time (see `persistence_path`).
    """

    def __init__(self, persistence_path=None, codebook=None):
        config = TemplateMinerConfig()
        persistence = None
        if persistence_path:
            from drain3.file_persistence import FilePersistence
            persistence = FilePersistence(persistence_path)
        self.miner = TemplateMiner(persistence_handler=persistence, config=config)
        # A promoted codebook (see codebook.py), checked before the
        # statistical miner on every line. One real example line per
        # cluster is kept here (not every line -- just the first) so a
        # later promotion pass can infer variable roles from a real
        # sample without needing to re-scan the source file.
        self.codebook = codebook
        self.examples_by_cluster = {}

    def parse_line(self, line):
        original = line.strip()
        drain_input = _normalize_delimiters(original)

        if self.codebook is not None:
            hit = self.codebook.match(original, _normalize_delimiters)
            if hit is not None:
                return hit

        result = self.miner.add_log_message(drain_input)
        template = result["template_mined"]
        cluster_id = result["cluster_id"]

        params = self.miner.extract_parameters(template, drain_input, exact_matching=False) or []
        variables = [p.value for p in params]
        tagged = [_tag_variable(v) for v in variables]

        if cluster_id not in self.examples_by_cluster:
            self.examples_by_cluster[cluster_id] = (original, tagged)

        return {
            "template": template,
            "cluster_id": cluster_id,
            "variables": tagged,
            "cluster_size": result.get("cluster_size"),
            "matched_learned_template": False,
        }
