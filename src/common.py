"""Shared settings + feature extraction.
The SAME function is used for training and for live detection, so the
model always sees features computed in exactly the same way."""
import math
from collections import Counter
import numpy as np

WINDOW_SECONDS = 5      # traffic is judged in 5-second windows
MIN_QUERIES = 5         # ignore windows with fewer queries (too little evidence)
THRESH_RESTRICT = 0.40  # prob >= 0.40 -> restrict (sinkhole) the domain
THRESH_BLOCK = 0.70     # prob >= 0.70 -> block the whole channel

FEATURES = [
    "n_queries", "qps", "avg_sub_len", "max_sub_len", "avg_entropy",
    "unique_subs", "unique_ratio", "rare_type_ratio",
    "mean_gap", "std_gap", "avg_labels",
]

RARE_TYPES = {"TXT", "NULL"}
QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 10: "NULL", 12: "PTR",
               15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def shannon_entropy(text: str) -> float:
    """Randomness of a string. English-like ~2-3, random Base32/64 ~4+."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def split_qname(qname: str):
    """'abc.def.attacker.test' -> ('abc.def', 'attacker.test')
    (simple rule: the last two labels are the base domain)"""
    qname = qname.lower().strip(".")
    labels = qname.split(".")
    if len(labels) <= 2:
        return "", qname
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def extract_features(queries):
    """queries = list of (timestamp, qname, qtype_name) for ONE host + domain
    inside ONE window. Returns a dict with every feature in FEATURES."""
    n = len(queries)
    ts = sorted(q[0] for q in queries)
    subs = [split_qname(q[1])[0] for q in queries]
    sub_lens = [len(s) for s in subs]
    entropies = [shannon_entropy(s.replace(".", "")) for s in subs if s]
    gaps = np.diff(ts) if n > 1 else np.array([0.0])
    unique = len(set(subs))
    return {
        "n_queries": n,
        "qps": n / WINDOW_SECONDS,
        "avg_sub_len": float(np.mean(sub_lens)),
        "max_sub_len": int(max(sub_lens)),
        "avg_entropy": float(np.mean(entropies)) if entropies else 0.0,
        "unique_subs": unique,
        "unique_ratio": unique / n,
        "rare_type_ratio": sum(1 for q in queries if q[2] in RARE_TYPES) / n,
        "mean_gap": float(np.mean(gaps)),
        "std_gap": float(np.std(gaps)),
        "avg_labels": float(np.mean([len(s.split(".")) if s else 0 for s in subs])),
    }
