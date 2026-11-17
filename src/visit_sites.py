"""A simulated visitor that browses all 10 lab websites.
Run it inside the victim container:
    docker compose exec victim python src/visit_sites.py
Options:  --rounds 2   --delay 6   --only gamezone"""
import argparse
import os
import random
import time
import urllib.parse
import urllib.request

from dnslib import DNSRecord

from sites_config import SITES, GROUP_IP

p = argparse.ArgumentParser()
p.add_argument("--rounds", type=int, default=2, help="how many times to visit every site")
p.add_argument("--delay", type=float, default=6, help="seconds between visits")
p.add_argument("--only", default=None, help="visit just one site id, e.g. gamezone")
a = p.parse_args()

RESOLVER = os.environ.get("RESOLVER_IP", "172.28.0.2")
DNS_PORT = int(os.environ.get("DNS_PORT", 53))
OVERRIDE = {"normal": os.environ.get("WEB_NORMAL"), "hacked": os.environ.get("WEB_HACKED")}  # "host:port" (testing only)


def resolve(name):
    """Ask the lab DNS resolver for the site's IP address (a real DNS lookup)."""
    try:
        data = DNSRecord.question(name, "A").send(RESOLVER, DNS_PORT, timeout=1)
        for rr in DNSRecord.parse(data).rr:
            return str(rr.rdata)
    except Exception:
        pass
    return None


def visit(site):
    group = "hacked" if site["hacked"] else "normal"
    ip = resolve(site["domain"])
    target = OVERRIDE[group] or f"{ip or GROUP_IP[group]}:80"
    headers = {"Host": site["domain"], "User-Agent": "Mozilla/5.0 (LabVisitor)"}
    try:
        with urllib.request.urlopen(urllib.request.Request(f"http://{target}/", headers=headers), timeout=5) as r:
            code = r.status
        extra = ""
        if random.random() < 0.6:   # also log in, like a real user
            body = urllib.parse.urlencode({"username": random.choice(["asha", "ravi", "meena", "john"]),
                                           "password": "Pass@" + str(random.randint(100, 999))}).encode()
            urllib.request.urlopen(urllib.request.Request(f"http://{target}/login", data=body, headers=headers),
                                   timeout=5).read()
            extra = " + login"
        print(f"[visit] {site['domain']:<20} -> {ip}  HTTP {code}{extra}", flush=True)
    except Exception as e:
        print(f"[visit] {site['domain']:<20} FAILED: {e}", flush=True)


targets = [s for s in SITES if not a.only or s["id"] == a.only]
print(f"[visit] browsing {len(targets)} websites, {a.rounds} round(s)", flush=True)
for rnd in range(a.rounds):
    order = targets[:]
    random.shuffle(order)
    for site in order:
        visit(site)
        time.sleep(a.delay)
print("[visit] done", flush=True)
