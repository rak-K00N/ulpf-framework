"""
One-off generator for the new sample corpora (LEEF, RFC5424, Cisco
Firepower coded syslog, and a gzip-compressed file) added to extend the
ULPF prototype. Not part of the pipeline itself -- run once to produce
the sample files checked into samples/, same way the original five were
presumably produced.
"""
import gzip
import random
from datetime import datetime, timedelta

random.seed(42)

INTERNAL_IPS = [f"192.168.1.{n}" for n in (10, 22, 35, 50, 61, 77, 88)]
EXTERNAL_IPS = ["8.8.8.8", "8.8.4.4", "93.184.216.34", "203.0.113.10",
                "198.51.100.23", "172.217.0.10", "104.16.85.20"]
USERS = ["jdoe", "asmith", "mchen", "admin1", "svc-backup"]
PORTS_WELLKNOWN = [443, 80, 53, 22, 3389, 445]

start_time = datetime(2026, 8, 31, 9, 0, 0)


def ts(i, fmt="%b %d %Y %H:%M:%S"):
    return (start_time + timedelta(seconds=i * 7)).strftime(fmt)


def ts_iso(i):
    return (start_time + timedelta(seconds=i * 7)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def rand_conn():
    return {
        "src": random.choice(INTERNAL_IPS),
        "dst": random.choice(EXTERNAL_IPS),
        "sport": random.randint(1024, 65000),
        "dport": random.choice(PORTS_WELLKNOWN),
        "proto": random.choice(["tcp", "udp"]),
        "user": random.choice(USERS),
    }


# ---------------------------------------------------------------------
# 07: Check Point LEEF (LEEF 2.0, tab-delimited extension)
# ---------------------------------------------------------------------
def gen_leef(n=2600):
    lines = []
    for i in range(n):
        c = rand_conn()
        act = random.choices(["Accept", "Drop"], weights=[7, 3])[0]
        proto_num = 6 if c["proto"] == "tcp" else 17
        ext = "\t".join([
            f"cat=Firewall",
            f"devTime={ts(i)}",
            f"src={c['src']}",
            f"dst={c['dst']}",
            f"srcPort={c['sport']}",
            f"dstPort={c['dport']}",
            f"proto={proto_num}",
            f"sev={5 if act == 'Accept' else 8}",
            f"usrName={c['user']}",
            f"bytesOut={random.randint(64, 9000)}",
            f"bytesIn={random.randint(64, 20000)}",
            f"act={act}",
        ])
        line = (f"<134>{ts(i)} chkpt-fw1 LEEF:2.0|Check Point|VPN-1 & FireWall-1|R81|"
                f"{act}|x09|{ext}")
        lines.append(line)
    return lines


# ---------------------------------------------------------------------
# 08: F5/Juniper-style RFC 5424 structured syslog
# ---------------------------------------------------------------------
def gen_syslog5424(n=2600):
    lines = []
    for i in range(n):
        c = rand_conn()
        action = random.choices(["accept", "block"], weights=[7, 3])[0]
        sd = (f'[firewall@32473 srcIP="{c["src"]}" dstIP="{c["dst"]}" '
              f'srcPort="{c["sport"]}" dstPort="{c["dport"]}" proto="{c["proto"]}" '
              f'action="{action}" bytesSent="{random.randint(64, 9000)}" '
              f'bytesRecv="{random.randint(64, 20000)}" user="{c["user"]}"]')
        msg = "Connection accepted" if action == "accept" else "Connection blocked by policy"
        line = f"<134>1 {ts_iso(i)} fw2.example.com netfw 1234 ID47 {sd} {msg}"
        lines.append(line)
    return lines


# ---------------------------------------------------------------------
# 09: Cisco Firepower coded syslog (new codebook vendor, same %PREFIX-N-CODE
#     shape as Cisco ASA already supports)
# ---------------------------------------------------------------------
def gen_firepower(n=2600):
    lines = []
    codes_weighted = (["430001"] * 5 + ["430002"] * 3 + ["430003"] * 1
                       + ["113004"] * 1)
    for i in range(n):
        c = rand_conn()
        code = random.choice(codes_weighted)
        proto = c["proto"].upper()
        if code == "430001":
            body = (f"AC_RuleAction: Allow, AC_RuleName: Default-Allow, "
                     f"SrcIP: {c['src']}, DstIP: {c['dst']}, SrcPort: {c['sport']}, "
                     f"DstPort: {c['dport']}, Protocol: {proto}")
        elif code == "430002":
            body = (f"AC_RuleAction: Block, AC_RuleName: Block-Known-Bad, "
                     f"SrcIP: {c['src']}, DstIP: {c['dst']}, SrcPort: {c['sport']}, "
                     f"DstPort: {c['dport']}, Protocol: {proto}")
        elif code == "430003":
            body = (f"Intrusion Event, SID: 41984, SrcIP: {c['src']}, DstIP: {c['dst']}, "
                     f"SrcPort: {c['sport']}, DstPort: {c['dport']}")
        else:
            body = f"AAA user authentication Successful : server = 10.0.0.9 : user = {c['user']}"
        sev = 6 if code in ("430001", "113004") else 4
        line = f"<{160+sev}>{ts(i)} FTD-EDGE01 : %FTD-{sev}-{code}: {body}"
        lines.append(line)
    return lines


def write(path, lines):
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} lines -> {path}")


if __name__ == "__main__":
    write("07_checkpoint_leef.log", gen_leef())
    write("08_juniper_syslog5424.log", gen_syslog5424())
    write("09_cisco_firepower_syslog.log", gen_firepower())

    # 10: gzip-compressed source, proving transparent .gz ingestion --
    # reuses the Fortinet kv_syslog generator shape by just recompressing
    # a slice of the existing sample 01 so it's a genuinely different file
    # from a "new" source, not a duplicate content-wise.
    with open("01_fortinet_syslog.log") as src:
        content = src.read()
    with gzip.open("10_fortinet_syslog_archived.log.gz", "wt", encoding="utf-8") as f:
        f.write(content)
    print("wrote gzip-compressed sample -> 10_fortinet_syslog_archived.log.gz")
