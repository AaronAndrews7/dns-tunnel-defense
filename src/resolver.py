"""Simple DNS server for the lab.
- Answers every query with a fake IP (so the lab works offline).
- Lab website names (freshmart.test, gamezone.test ...) resolve to the web-server containers.
- Plays the attacker's name server for the C2 domains (they receive the tunnel data).
- Refuses domains listed in blocked_domains.txt (written by the detector)."""
import os
import socket
from dnslib import DNSRecord, RR, QTYPE, RCODE, A, AAAA, TXT

from sites_config import SITE_IPS

DATA_DIR = os.environ.get("DATA_DIR", "/data")
HOST = os.environ.get("DNS_HOST", "0.0.0.0")
PORT = int(os.environ.get("DNS_PORT", 53))
BLOCKFILE = os.path.join(DATA_DIR, "blocked_domains.txt")
_cache = {"mtime": 0, "domains": set()}


def blocked_domains():
    try:
        m = os.stat(BLOCKFILE).st_mtime
        if m != _cache["mtime"]:
            with open(BLOCKFILE) as f:
                _cache["domains"] = {l.strip() for l in f if l.strip()}
            _cache["mtime"] = m
    except FileNotFoundError:
        _cache["domains"] = set()
    return _cache["domains"]


def is_blocked(qname):
    return any(qname == d or qname.endswith("." + d) for d in blocked_domains())


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    print(f"[resolver] listening on {HOST}:{PORT}  ({len(SITE_IPS)} lab websites known)", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            req = DNSRecord.parse(data)
            qname = str(req.q.qname).rstrip(".").lower()
            qtype = QTYPE.get(req.q.qtype, str(req.q.qtype))
            reply = req.reply()
            if is_blocked(qname):
                reply.header.rcode = RCODE.REFUSED
            elif qtype == "A":
                ip = SITE_IPS.get(".".join(qname.split(".")[-2:]), "10.10.10.10")
                reply.add_answer(RR(req.q.qname, QTYPE.A, rdata=A(ip), ttl=1))
            elif qtype == "AAAA":
                reply.add_answer(RR(req.q.qname, QTYPE.AAAA, rdata=AAAA("fd00::10"), ttl=1))
            elif qtype == "TXT":
                reply.add_answer(RR(req.q.qname, QTYPE.TXT, rdata=TXT("ack"), ttl=1))
            sock.sendto(reply.pack(), addr)
        except Exception as e:  # never crash the server
            print("[resolver] error:", e, flush=True)


if __name__ == "__main__":
    main()
