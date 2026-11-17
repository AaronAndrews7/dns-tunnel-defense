"""The VICTIM machine doing normal browsing: bursts of DNS lookups
(like loading web pages), then a pause."""
import os
import random
import time
from dnslib import DNSRecord
from traffic_gen import normal_queries

RESOLVER = os.environ.get("RESOLVER_IP", "172.28.0.2")
PORT = int(os.environ.get("DNS_PORT", 53))
rng = random.Random()


def lookup(name, qtype):
    try:
        data = DNSRecord.question(name, qtype).send(RESOLVER, PORT, timeout=1)
        return "REFUSED" if DNSRecord.parse(data).header.rcode == 5 else "OK"
    except Exception:
        return "TIMEOUT"


print(f"[victim] normal browsing -> resolver {RESOLVER}:{PORT}", flush=True)
while True:
    burst = normal_queries(rng)
    results = {"OK": 0, "REFUSED": 0, "TIMEOUT": 0}
    for name, qtype in burst:
        results[lookup(name, qtype)] += 1
        time.sleep(rng.uniform(0.02, 0.3))
    print(f"[victim] page load: {len(burst)} lookups for {burst[0][0].split('.', 1)[-1]} -> {results}", flush=True)
    time.sleep(rng.uniform(3, 8))
