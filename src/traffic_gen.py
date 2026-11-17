"""Generates realistic NORMAL and TUNNEL DNS traffic.
Used (1) to build the training dataset and (2) by the victim/attacker scripts."""
import base64
import random
import string

from common import MIN_QUERIES, WINDOW_SECONDS

NORMAL_DOMAINS = ["google.com", "github.com", "example.com", "wikipedia.org",
                  "youtube.com", "microsoft.com", "amazon.com",
                  "stackoverflow.com", "python.org", "openai.com"]
NORMAL_SUBS = ["www", "api", "mail", "cdn", "static", "docs", "login",
               "images", "fonts", "accounts", "maps", "assets", "support", "m"]
CDN_DOMAINS = ["cloudfront.net", "akamaiedge.net", "googlevideo.com", "fastly.net"]
TUNNEL_DOMAINS = ["attacker.test", "evil-c2.com", "sync-update.net", "cdn-check.org"]

ALNUM = string.ascii_lowercase + string.digits


def random_label(rng, length, alphabet=ALNUM):
    return "".join(rng.choice(alphabet) for _ in range(length))


def encode_chunk(raw: bytes, encoding: str, length: int) -> str:
    """Turn raw bytes into a DNS-safe label (this is what a tunnel does)."""
    if encoding == "base32":
        s = base64.b32encode(raw).decode().rstrip("=").lower()
    elif encoding == "hex":
        s = raw.hex()
    else:  # base64
        s = base64.urlsafe_b64encode(raw).decode().rstrip("=").lower()
    return s[:length]


def normal_queries(rng):
    """One burst of normal-looking queries (like loading a web page).
    Returns a list of (qname, qtype). Includes HARD cases that look a bit
    like tunnels (busy CDN traffic, mail TXT lookups) so the model has to
    really learn, instead of getting a perfect score."""
    kind = rng.choices(["browse", "cdn_hash", "mixed", "streaming", "mail_txt"],
                       [0.45, 0.2, 0.1, 0.1, 0.15])[0]
    n = rng.randint(30, 100) if kind == "streaming" else rng.randint(MIN_QUERIES, 40)
    domain = rng.choice(NORMAL_DOMAINS)
    names, types = [], None
    for _ in range(n):
        if kind == "browse" or (kind == "mixed" and rng.random() < 0.6):
            names.append(f"{rng.choice(NORMAL_SUBS)}.{domain}" if rng.random() < 0.9 else domain)
        elif kind == "mail_txt":   # SPF / DKIM / DMARC style lookups
            sel = rng.choice(["selector1", "selector2", "google", "default", "s1", "k1"])
            names.append(rng.choice([f"{sel}._domainkey.{domain}", f"_dmarc.{domain}",
                                     f"mail.{domain}", f"_spf.{domain}"]))
        else:  # hash-like CDN names: look random but are short and type A
            cdn = rng.choice(CDN_DOMAINS) if kind != "mixed" else domain
            hi = 32 if kind == "streaming" else 22
            names.append(f"{random_label(rng, rng.randint(8, hi))}.{cdn}")
    if kind == "mail_txt":
        types = rng.choices(["TXT", "A", "MX"], [0.7, 0.2, 0.1], k=n)
    else:
        types = rng.choices(["A", "AAAA", "MX", "TXT"], [0.75, 0.2, 0.03, 0.02], k=n)
    return list(zip(names, types))


def tunnel_queries(rng, n=None, encoding=None, chunk_len=None, domain=None):
    """One burst of tunnel queries: random data encoded into subdomains."""
    if n is None:
        n = rng.randint(MIN_QUERIES, 15) if rng.random() < 0.25 else rng.randint(20, 200)
    encoding = encoding or rng.choice(["base32", "hex", "base64"])
    domain = domain or rng.choice(TUNNEL_DOMAINS)
    out = []
    stealth_short = rng.random() < 0.25
    stealth_types = rng.random() < 0.2      # only A/AAAA (looks more normal)
    for _ in range(n):
        # 25% of tunnels use short chunks (stealthier, harder to detect)
        length = chunk_len or (rng.randint(10, 19) if stealth_short else rng.randint(20, 60))
        label = encode_chunk(rng.randbytes(length), encoding, length)
        if length > 40 and rng.random() < 0.3:   # split over two labels
            label = label[:length // 2] + "." + label[length // 2:]
        if stealth_types:
            qtype = rng.choice(["A", "AAAA"])
        else:
            qtype = rng.choices(["TXT", "NULL", "A", "CNAME", "AAAA"],
                                [0.45, 0.15, 0.15, 0.10, 0.15])[0]
        out.append((f"{label}.{domain}", qtype))
    return out


def timestamps(rng, n, periodic):
    """Fake arrival times inside one window.
    Tunnels are often evenly spaced (periodic); human traffic is irregular."""
    if periodic:
        step = WINDOW_SECONDS / n
        return [i * step + rng.uniform(-0.1, 0.1) * step for i in range(n)]
    return sorted(rng.uniform(0, WINDOW_SECONDS) for _ in range(n))


def make_window(rng, label):
    """Return a list of (ts, qname, qtype) = one labelled training window."""
    if label == 0:
        qs = normal_queries(rng)
        ts = timestamps(rng, len(qs), periodic=False)
    else:
        qs = tunnel_queries(rng)
        ts = timestamps(rng, len(qs), periodic=rng.random() < 0.6)
    return [(t, q, ty) for t, (q, ty) in zip(ts, qs)]
