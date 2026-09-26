"""
Self-writing parser codebooks.

Every "unknown"-format line currently gets re-clustered from scratch by
Drain3's statistical template miner (parsers/drain_fallback.py) -- every
run, on every machine, forever. That's the same cost the rest of the
industry pays too, just paid differently: Splunk/Elastic don't even
attempt automatic clustering for a truly custom source -- a human writes
props.conf/transforms.conf regex or an ingest pipeline by hand, once per
format, per SIEM (see any Splunk community thread on onboarding a new
sourcetype). Neither approach produces a durable, portable artifact from
what's already been learned.

This module is the fix: once a Drain cluster has been seen enough times
to be statistically stable (cluster.size >= MIN_OCCURRENCES), it gets
"promoted" into a codebook entry -- a compiled regex plus a per-variable
shape tag, synthesized directly from the cluster's own template and one
real example line. A codebook is one JSON file. It can be saved, copied
to another air-gapped machine over USB, and loaded there -- a format
learned once, on one box, never has to be re-learned cold anywhere else.
Matching against a promoted entry is a single regex call instead of a
statistical miner traversal, so promoted lines also parse faster.

Deliberately NOT a black box: every entry is inspectable JSON (the
literal template, the compiled regex, a real sample line, how many times
it was seen) -- review_summary() below is meant to be read by a human
before a codebook is trusted, not auto-applied silently. The regex
generator is restricted to escaped-literal segments plus simple
non-nested capture groups specifically so it can never produce
catastrophic-backtracking (ReDoS) patterns -- an auto-generated parser
that can hang the pipeline on crafted input would be an unacceptable
risk to ship into an air-gapped/defense deployment.
"""
import hashlib
import json
import re
import time

MIN_OCCURRENCES = 20  # a cluster must be seen this many times before it's trusted enough to promote


def _template_signature(template):
    return hashlib.sha1(template.encode("utf-8")).hexdigest()[:16]


def compile_template_regex(template):
    """'Failed password for <*> from <*> port <*> ssh2' -> a regex with
    one non-greedy capturing group per <*>, everything else escaped as
    literal text. No nested quantifiers, no backreferences, no
    alternation -- structurally incapable of catastrophic backtracking
    regardless of what the template contains, which matters because
    templates come from untrusted log input, not a human author."""
    parts = template.split("<*>")
    pattern = "^" + r"(.+?)".join(re.escape(p) for p in parts) + "$"
    return re.compile(pattern)


def infer_roles(sample_variables):
    """Human-readable role per variable slot, for the audit printout
    only (matching itself re-tags shapes fresh every time via
    _tag_variable, so this list documents a promotion decision -- it
    isn't re-consulted at match time, and can't drift out of sync with
    the matching logic as a result)."""
    roles = []
    ip_seen = port_seen = 0
    for tagged in sample_variables:
        t = tagged.get("guessed_type")
        if t == "ip":
            role = "src_ip" if ip_seen == 0 else ("dst_ip" if ip_seen == 1 else "ip")
            ip_seen += 1
        elif t == "port_or_number":
            role = "src_port" if port_seen == 0 else ("dst_port" if port_seen == 1 else "port")
            port_seen += 1
        else:
            role = t or "unknown"
        roles.append(role)
    return roles


class LearnedCodebook:
    """A set of promoted templates. Matching is indexed by token count --
    the same first-level bucketing trick Drain3's own tree-search already
    uses (a line with 12 whitespace tokens can only ever match a template
    with exactly 12 tokens, so there's no reason to even attempt a regex
    match against templates of a different shape). Without this, a global
    codebook accumulated across many different source formats would make
    every line pay for a full linear scan through every irrelevant
    template before reaching the one that actually applies -- exactly the
    kind of naive-and-slow mistake this feature exists to avoid causing
    elsewhere in the pipeline."""

    def __init__(self):
        self.entries = []
        self._by_token_count = {}

    def _reindex(self):
        self.entries.sort(key=lambda e: -e["sample_count"])
        self._by_token_count = {}
        for e in self.entries:
            n = len(e["template"].split())
            self._by_token_count.setdefault(n, []).append(e)

    def add(self, template, sample_variables, sample_count, sample_line, source_name):
        sig = _template_signature(template)
        if any(e["signature"] == sig for e in self.entries):
            return False
        self.entries.append({
            "signature": sig,
            "template": template,
            "regex": compile_template_regex(template).pattern,
            "roles": infer_roles(sample_variables),
            "sample_count": sample_count,
            "sample_line": sample_line[:200],
            "learned_from_source": source_name,
            "learned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        self._reindex()
        return True

    def merge(self, other):
        """Combines two codebooks (e.g. one brought in from another
        machine with one learned locally this run), keeping whichever
        copy of a duplicate template has the higher sample_count."""
        by_sig = {e["signature"]: e for e in self.entries}
        for e in other.entries:
            existing = by_sig.get(e["signature"])
            if existing is None or e["sample_count"] > existing["sample_count"]:
                by_sig[e["signature"]] = e
        self.entries = list(by_sig.values())
        self._reindex()

    def save(self, path):
        with open(path, "w") as f:
            json.dump({"codebook_version": 1, "entries": self.entries}, f, indent=2)
        return path

    @classmethod
    def load(cls, path):
        cb = cls()
        with open(path) as f:
            data = json.load(f)
        cb.entries = data.get("entries", [])
        cb._reindex()
        return cb

    def match(self, raw_line, normalize_fn):
        """normalize_fn is drain_fallback._normalize_delimiters -- passed
        in rather than imported, to avoid a circular import between this
        module and drain_fallback.py. Returns a drain_result-shaped dict
        (same keys DrainFallbackParser.parse_line produces) so it's a
        drop-in input to normalizer.normalize_drain() with zero
        duplicated normalization logic, or None if nothing matched."""
        from parsers.drain_fallback import _tag_variable
        normalized = normalize_fn(raw_line.strip())
        candidates = self._by_token_count.get(len(normalized.split()))
        if not candidates:
            return None
        for entry in candidates:
            compiled = entry.get("_compiled")
            if compiled is None:
                compiled = entry["_compiled"] = re.compile(entry["regex"])
            m = compiled.match(normalized)
            if not m:
                continue
            variables = [_tag_variable(v) for v in m.groups()]
            return {
                "template": entry["template"],
                "cluster_id": f"learned:{entry['signature']}",
                "variables": variables,
                "cluster_size": entry["sample_count"],
                "matched_learned_template": True,
            }
        return None


def promote_stable_clusters(drain_parser, source_name, min_occurrences=MIN_OCCURRENCES, existing=None):
    """Walks one DrainFallbackParser's miner state after processing and
    promotes every cluster stable enough to trust. Returns (codebook,
    list_of_newly_promoted (template, sample_count) pairs) -- the second
    return value is exactly what a human-facing review printout needs,
    see run_demo.py."""
    codebook = existing or LearnedCodebook()
    promoted = []
    for cluster in drain_parser.miner.drain.clusters:
        if cluster.size < min_occurrences:
            continue
        template = cluster.get_template()
        example = drain_parser.examples_by_cluster.get(cluster.cluster_id)
        if not example:
            continue
        raw_line, tagged_variables = example
        if codebook.add(template, tagged_variables, cluster.size, raw_line, source_name):
            promoted.append((template, cluster.size))
    return codebook, promoted


def review_summary(promoted):
    """Human-readable audit text for newly-promoted templates -- meant to
    actually be read before a codebook file is trusted or shipped
    anywhere, not auto-applied silently. `promoted` is a list of
    (source_name, template, sample_count) triples."""
    if not promoted:
        return "  (no new templates were stable enough to promote this run)"
    lines = []
    for source_name, template, count in sorted(promoted, key=lambda p: -p[2]):
        lines.append(f"  [{count:5d}x from {source_name:28s}]  {template}")
    return "\n".join(lines)
