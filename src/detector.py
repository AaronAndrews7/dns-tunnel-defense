"""DETECTION + RESPONSE ENGINE (with EXPLAINABLE ALERTS).
1. Sniff DNS queries with Scapy.
2. Every 5 s group them by (source host, base domain) and extract features.
3. Random Forest gives P(tunnel).
4. If suspicious, EXPLAIN why: exact Shapley values show how much each
   feature pushed the risk up compared with a typical normal window.
5. Respond:  <40% allow | 40-70% restrict domain | >=70% block channel.
6. Log every decision (and its explanation) to SQLite for the dashboard."""
import json
import math
import os
import sqlite3
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from scapy.all import sniff, DNS, DNSQR, IP, UDP

from common import (WINDOW_SECONDS, MIN_QUERIES, THRESH_RESTRICT, THRESH_BLOCK,
                    FEATURES, QTYPE_NAMES, extract_features, split_qname)

DATA_DIR = os.environ.get("DATA_DIR", "/data")
MODEL_PATH = os.environ.get("MODEL_PATH", "/app/models/rf_model.joblib")
IFACE = os.environ.get("SNIFF_IFACE") or None
DNS_PORT = int(os.environ.get("DNS_PORT", 53))
USE_IPTABLES = os.environ.get("USE_IPTABLES", "1") == "1"
DOMAIN_BLOCK_SECONDS = int(os.environ.get("DOMAIN_BLOCK_SECONDS", 300))
HOST_BLOCK_SECONDS = int(os.environ.get("HOST_BLOCK_SECONDS", 60))

DB_PATH = os.path.join(DATA_DIR, "detections.db")
BLOCKFILE = os.path.join(DATA_DIR, "blocked_domains.txt")
DATASET_PATH = os.path.join(DATA_DIR, "dataset.csv")

# plain-English names used in the explanations
FEATURE_TEXT = {
    "n_queries": "number of queries", "qps": "queries per second",
    "avg_sub_len": "average subdomain length", "max_sub_len": "longest subdomain",
    "avg_entropy": "name randomness (entropy)", "unique_subs": "unique subdomains",
    "unique_ratio": "share of unique names", "rare_type_ratio": "TXT/NULL record share",
    "mean_gap": "average gap between queries", "std_gap": "timing irregularity",
    "avg_labels": "labels per subdomain",
}

lock = threading.Lock()
buffers = defaultdict(list)       # (src, domain) -> [(ts, qname, qtype)]
blocked_domains = {}              # domain -> expiry time
blocked_hosts = {}                # ip -> expiry time

# ---------- load model ----------
if not os.path.exists(MODEL_PATH):
    raise SystemExit(f"Model not found at {MODEL_PATH}. Run the trainer first:  "
                     f"docker compose run --rm trainer")
bundle = joblib.load(MODEL_PATH)
model = bundle["model"]
TUNNEL_IDX = list(model.classes_).index(1)

# ---------- explainability setup ----------
N = len(FEATURES)
MASKS = ((np.arange(2 ** N)[:, None] >> np.arange(N)) & 1).astype(bool)   # all 2^N on/off combinations
SIZES = MASKS.sum(axis=1)
FACT = [math.factorial(i) for i in range(N + 1)]
SHAP_W = np.array([FACT[k] * FACT[N - k - 1] / FACT[N] for k in range(N)])


def load_baseline():
    """A 'typical normal window' = median of every feature over the normal training rows."""
    try:
        d = pd.read_csv(DATASET_PATH)
        return d[d["label"] == 0][FEATURES].median().values.astype(float)
    except Exception as e:
        print(f"[detector] explanations disabled (could not read {DATASET_PATH}: {e})", flush=True)
        return None


BASELINE = load_baseline()


def explain(x_vals):
    """Exact Shapley values: how many probability points each feature added
    compared with the typical normal window. They add up to
    P(this window) - P(typical normal window)."""
    data = np.where(MASKS, x_vals, BASELINE)                    # 2048 mixed windows
    v = model.predict_proba(pd.DataFrame(data, columns=FEATURES))[:, TUNNEL_IDX]
    phi = np.zeros(N)
    for i in range(N):
        idx = np.nonzero(~MASKS[:, i])[0]                       # combinations without feature i
        phi[i] = np.sum(SHAP_W[SIZES[idx]] * (v[idx | (1 << i)] - v[idx]))
    return phi, float(v[0])


def build_explanation(feats):
    if BASELINE is None:
        return None
    x = np.array([feats[k] for k in FEATURES], dtype=float)
    phi, base_prob = explain(x)
    order = np.argsort(-phi)
    top = [{"feature": FEATURES[i], "label": FEATURE_TEXT[FEATURES[i]],
            "value": round(float(x[i]), 3), "normal": round(float(BASELINE[i]), 3),
            "impact": round(float(phi[i]) * 100, 1)} for i in order[:5] if phi[i] > 0.005]
    return {"base_prob": round(base_prob * 100, 1), "top": top}


# ---------- database ----------
os.makedirs(DATA_DIR, exist_ok=True)
db = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
db.execute("""CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, src TEXT, domain TEXT,
    n_queries INTEGER, qps REAL, avg_entropy REAL, avg_sub_len REAL,
    unique_subs INTEGER, prob REAL, action TEXT, explanation TEXT)""")
try:                                   # old database from before explanations existed
    db.execute("ALTER TABLE detections ADD COLUMN explanation TEXT")
except sqlite3.OperationalError:
    pass
db.commit()


# ---------- firewall helpers ----------
def iptables(*args):
    if not USE_IPTABLES:
        return True
    try:
        r = subprocess.run(["iptables", *args], capture_output=True, text=True)
        return r.returncode == 0
    except Exception as e:
        print("[detector] iptables problem:", e, flush=True)
        return False


def rule(ip):
    return ["INPUT", "-s", ip, "-p", "udp", "--dport", str(DNS_PORT), "-j", "DROP"]


def block_host(ip):
    if ip not in blocked_hosts:
        if not iptables("-C", *rule(ip)):          # add only if rule not present
            ok = iptables("-I", *rule(ip))
            print(f"[detector] FIREWALL: DROP DNS from {ip} ({'ok' if ok else 'iptables FAILED'})", flush=True)
    blocked_hosts[ip] = time.time() + HOST_BLOCK_SECONDS


def block_domain(domain):
    if domain not in blocked_domains:
        print(f"[detector] SINKHOLE: refusing all queries for {domain}", flush=True)
    blocked_domains[domain] = time.time() + DOMAIN_BLOCK_SECONDS


def expire_blocks():
    now = time.time()
    for ip in [i for i, t in blocked_hosts.items() if t < now]:
        iptables("-D", *rule(ip))
        del blocked_hosts[ip]
        print(f"[detector] firewall rule for {ip} expired", flush=True)
    for d in [d for d, t in blocked_domains.items() if t < now]:
        del blocked_domains[d]
        print(f"[detector] domain block for {d} expired", flush=True)
    with open(BLOCKFILE, "w") as f:
        f.write("\n".join(blocked_domains))


# ---------- packet capture ----------
def on_packet(pkt):
    # (we filter in Python, so no libpcap is needed)
    if not (pkt.haslayer(UDP) and pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt.haslayer(IP)):
        return
    if pkt[UDP].dport != DNS_PORT or pkt[DNS].qr != 0:   # only queries sent TO the resolver
        return
    q = pkt[DNSQR]
    qname = q.qname.decode(errors="ignore") if isinstance(q.qname, bytes) else str(q.qname)
    qname = qname.lower().rstrip(".")
    _, base = split_qname(qname)
    qtype = QTYPE_NAMES.get(q.qtype, str(q.qtype))
    with lock:
        buffers[(pkt[IP].src, base)].append((time.time(), qname, qtype))


# ---------- decision logic ----------
def decide(src, domain, prob):
    if prob < THRESH_RESTRICT:
        return "ALLOW"
    if prob < THRESH_BLOCK:
        block_domain(domain)
        return "RESTRICT_DOMAIN"
    block_domain(domain)
    block_host(src)
    return "BLOCK_CHANNEL"


def analyse_window(src, domain, qs):
    """Score one (host, domain) window, explain it if suspicious, respond, log."""
    f = extract_features(qs)
    X = pd.DataFrame([[f[k] for k in FEATURES]], columns=FEATURES)
    prob = float(model.predict_proba(X)[0][TUNNEL_IDX])
    action = decide(src, domain, prob)
    expl = build_explanation(f) if action != "ALLOW" else None
    db.execute("INSERT INTO detections (ts,src,domain,n_queries,qps,avg_entropy,avg_sub_len,"
               "unique_subs,prob,action,explanation) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
               (datetime.now().isoformat(timespec="seconds"), src, domain, f["n_queries"],
                f["qps"], f["avg_entropy"], f["avg_sub_len"], f["unique_subs"], prob, action,
                json.dumps(expl) if expl else None))
    db.commit()
    print(f"[detector] {src} -> {domain:<22} q={f['n_queries']:<4} entropy={f['avg_entropy']:.2f} "
          f"uniq={f['unique_subs']:<4} P(tunnel)={prob*100:5.1f}%  => {action}", flush=True)
    if expl and expl["top"]:
        why = ", ".join(f"{t['label']} {t['value']:g} (normal {t['normal']:g}) +{t['impact']:.0f}%"
                        for t in expl["top"][:3])
        print(f"[detector]    WHY: {why}", flush=True)
    return prob, action, expl


def evaluator():
    while True:
        time.sleep(WINDOW_SECONDS)
        with lock:
            snapshot = dict(buffers)
            buffers.clear()
        for (src, domain), qs in snapshot.items():
            if len(qs) >= MIN_QUERIES:
                analyse_window(src, domain, qs)
        expire_blocks()


if __name__ == "__main__":
    open(BLOCKFILE, "w").close()          # clean start: empty block list
    print(f"[detector] model loaded. window={WINDOW_SECONDS}s  thresholds: "
          f"{THRESH_RESTRICT:.0%} restrict, {THRESH_BLOCK:.0%} block  iptables={USE_IPTABLES}  "
          f"explanations={'on' if BASELINE is not None else 'off'}", flush=True)
    threading.Thread(target=evaluator, daemon=True).start()
    sniff(prn=on_packet, store=False, iface=IFACE)
