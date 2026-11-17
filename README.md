# DNS Tunneling Defense – Complete Beginner Guide

## 1. What is this project? (plain English)
**DNS** turns names (google.com) into IP addresses. Firewalls usually allow DNS, so attackers hide stolen data inside DNS questions, e.g. `ORSXG5DJNZTSA3DPEB2GQZJA.attacker.test`. That is **DNS tunneling**.

Your project builds a safe lab that:
1. **Simulates** normal users and a tunneling attacker (Docker containers on your own PC).
2. **Captures** the DNS packets (Scapy).
3. **Extracts features** (length, randomness/entropy, query rate, unique subdomains, record type, timing).
4. Uses a **Random Forest** model to give a tunnel probability.
5. **Responds automatically**: <40% allow, 40–70% restrict the domain, ≥70% block the channel (domain refused + firewall rule).
6. Shows everything on a **live dashboard**.

Flow: `victim -> resolver (captured by detector) -> features -> ML -> block -> dashboard`

## 2. Install (one time)
1. **Docker Desktop** (https://www.docker.com/products/docker-desktop) – install, restart PC, open it and wait until it says "running". On Windows keep "Use WSL 2" ticked.
2. **VS Code** (optional, to read code): https://code.visualstudio.com
3. Unzip `dns-tunnel-defense.zip` (e.g. to `C:\projects\dns-tunnel-defense`).
4. Open a terminal **inside that folder**: Windows – open the folder, click the address bar, type `cmd`, Enter. Then check:
```
docker --version
docker compose version
```
Both must print a version.

## 3. Run the project (copy-paste, in order)
**Step 1 – Build the image (5–10 min first time)**
```
docker compose build
```
**Step 2 – Create data + train the model**
```
docker compose run --rm trainer
```
You will see accuracy / precision / recall / F1 and a confusion matrix. New files appear in `reports/` (confusion_matrix.png, feature_importance.png, metrics.txt), `data/dataset.csv` and `models/rf_model.joblib`.

**Step 3 – Start the lab**
```
docker compose up -d
docker compose ps
```
You should see 4 running containers: dns_resolver, dns_detector, victim, dashboard.

**Step 4 – Open the dashboard:** http://localhost:8501 (normal traffic = green dots, low %).

**Step 5 – Watch live logs (open 2 more terminals in the same folder)**
```
docker compose logs -f detector
docker compose logs -f victim
```

## 4. The demo (attack!)
In a new terminal:
```
docker compose exec victim python src/tunnel_attack.py
```
What happens: the attacker "steals" a fake file through DNS queries at 15/s.
- Detector log: `P(tunnel)= 84% => BLOCK_CHANNEL`
- Dashboard: red dots, "Currently blocked: attacker.test"
- Attack terminal: queries FAIL, then `CHANNEL DISRUPTED ... bytes leaked`
- Normal browsing stops for ~60 s (host firewalled), then recovers automatically.

Other attack variants (good for report): 
```
docker compose exec victim python src/tunnel_attack.py --rate 3          # slow & stealthy
docker compose exec victim python src/tunnel_attack.py --enc hex --type A
```
**Repeat the demo from a clean state:** `docker compose restart detector`

**Show packets (proof / Wireshark):**
```
docker compose exec resolver tcpdump -i eth0 -n -c 20 udp port 53
docker compose exec resolver tcpdump -i eth0 -n -w /data/capture.pcap -c 300 udp port 53
```
The second one saves `data/capture.pcap` – open it in Wireshark on your PC (filter: `dns`).

**Stop everything:** `docker compose down`

## 5. Files – what each one does
| File | Purpose |
|---|---|
| `docker-compose.yml` | Defines the lab: resolver, detector, victim, dashboard, trainer |
| `src/common.py` | Settings (window 5 s, thresholds) + **feature extraction** |
| `src/traffic_gen.py` | Creates normal + tunnel DNS traffic (training input + victim/attacker) |
| `src/make_dataset.py` | Builds labelled `dataset.csv` (3000 normal + 3000 tunnel windows) |
| `src/train_model.py` | Trains/evaluates Random Forest, saves model + graphs |
| `src/resolver.py` | DNS server (also acts as attacker's name server); obeys blocklist |
| `src/victim_normal.py` | Victim doing normal browsing |
| `src/tunnel_attack.py` | Simulated tunneling attack |
| `src/detector.py` | Scapy sniffing + ML + response (iptables, sinkhole) + SQLite log |
| `src/dashboard.py` | Streamlit live dashboard |

## 6. "Where does the input come from?" (important for viva)
- **Training input:** simulated by `traffic_gen.py` (normal = web-page style lookups, CDN names, mail TXT lookups; tunnel = random data encoded as Base32/Base64/hex in subdomains, various record types, fast and slow).
- **Live input:** real DNS packets captured with Scapy from the lab network.
- **Features per (host, domain, 5-second window):**
  - `avg_sub_len`, `max_sub_len` – tunnels use long names
  - `avg_entropy` – randomness of the subdomain (tunnel ~4+, normal ~2–3)
  - `qps`, `n_queries` – tunnels send many queries
  - `unique_subs`, `unique_ratio` – every tunnel query has a new name
  - `rare_type_ratio` – share of TXT/NULL queries
  - `mean_gap`, `std_gap` – timing regularity
  - `avg_labels` – number of labels in subdomain

## 7. For your report/PPT
Add: `reports/confusion_matrix.png`, `reports/feature_importance.png`, `reports/metrics.txt`, dashboard screenshots (before attack, during, after), detector log screenshot, tcpdump/Wireshark screenshot, attacker "CHANNEL DISRUPTED" screenshot.

## 8. Be honest about limitations
- Accuracy will be ~99–100% because training data is simulated; real networks are messier. Say this clearly – it shows maturity.
- Base-domain rule is simple (last two labels), so `co.uk`-style domains are not handled.
- Only DNS over UDP port 53 (not DoH/DoT/TCP).
- Future work: real datasets (e.g. CIC-Bell-DNS-2021), more tools (iodine, dnscat2) in the lab, DoH detection, online learning.

## 9. Troubleshooting
| Problem | Fix |
|---|---|
| `docker: command not found` | Open Docker Desktop first; reopen terminal |
| Port 8501 or 53 in use | Close the other program, or change port in compose file |
| Detector: "Model not found" | Run Step 2 (trainer) first, then `docker compose restart detector` |
| Dashboard says "Waiting for data" | Wait ~15 s; check `docker compose ps` and detector logs |
| Detector says `iptables FAILED` | Domain blocking still works. Set `USE_IPTABLES=0` in compose to silence it |
| Changed code | Code is mounted live: `docker compose restart <service>` |
| Start from scratch | `docker compose down`, delete `data/*` and `models/*`, repeat Step 2 |

## 10. Likely viva questions
1. **What is DNS tunneling?** Hiding data in DNS queries/responses to bypass firewalls.
2. **Why Random Forest?** Handles mixed numeric features, resists overfitting, gives probabilities and feature importance, fast enough for real time.
3. **Why entropy?** Encoded data looks random, so its character entropy is higher than human-readable names.
4. **How do you reduce false positives?** Hard normal cases in training (CDN, mail TXT), 3 confidence tiers, auto-expiring blocks.
5. **Why 5-second windows?** Rate and uniqueness need several queries to be meaningful.
6. **Why Docker?** Safe, isolated, repeatable lab.
7. **How is blocking done?** Domain sinkhole (resolver refuses it) + iptables DROP of the host's DNS traffic, auto-removed after 60 s.
8. **Limitations?** See section 8.
