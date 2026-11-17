"""LIVE DASHBOARD (Streamlit) - dark "security operations" style.
Open http://localhost:8501"""
import json
import os
import sqlite3
import time
from datetime import datetime

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from sites_config import SITES

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "detections.db")
BLOCKFILE = os.path.join(DATA_DIR, "blocked_domains.txt")

GREEN, AMBER, RED, BLUE = "#22c55e", "#f59e0b", "#ef4444", "#38bdf8"
TEXT, MUTED, CARD, BORDER = "#e6edf7", "#8b9ab8", "#111a2e", "#1f2a44"
ACTION_COLOR = {"ALLOW": GREEN, "RESTRICT_DOMAIN": AMBER, "BLOCK_CHANNEL": RED}
ACTION_LABEL = {"ALLOW": "Allowed", "RESTRICT_DOMAIN": "Restricted", "BLOCK_CHANNEL": "Blocked"}

st.set_page_config(page_title="DNS Tunneling Defense", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp { background: radial-gradient(1200px 600px at 10% -10%, #14213d 0%, #0b1220 55%); color: #e6edf7; }
header[data-testid="stHeader"] { background: transparent; }
[data-testid="stSidebar"] { background: #0e1627; border-right: 1px solid #1f2a44; }
[data-testid="stSidebar"] * { color: #e6edf7 !important; }
.block-container { padding-top: 1.6rem; max-width: 1400px; }
.hero { display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:10px; margin-bottom:14px; }
.hero h1 { margin:0; font-size:1.9rem; color:#e6edf7; letter-spacing:.2px; }
.hero p { margin:2px 0 0 0; color:#8b9ab8; font-size:.95rem; }
.live { background:#0f2a1c; color:#22c55e; border:1px solid #14532d; padding:6px 14px; border-radius:999px; font-size:.85rem; font-weight:600; }
.live .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:#22c55e; margin-right:8px; animation:pulse 1.4s infinite; }
@keyframes pulse { 0%{opacity:1} 50%{opacity:.25} 100%{opacity:1} }
.banner { border-radius:14px; padding:18px 22px; margin:6px 0 18px 0; display:flex; align-items:center; gap:16px; }
.banner .icon { font-size:2rem; }
.banner .big { font-size:1.25rem; font-weight:700; }
.banner .small { font-size:.92rem; opacity:.85; margin-top:2px; }
.banner.ok { background:linear-gradient(90deg,#0f2a1c,#0b1f17); border:1px solid #14532d; color:#86efac; }
.banner.bad { background:linear-gradient(90deg,#3b1219,#2a0e13); border:1px solid #7f1d1d; color:#fca5a5; }
.kpi { background:#111a2e; border:1px solid #1f2a44; border-radius:14px; padding:16px 18px; }
.kpi .label { color:#8b9ab8; font-size:.82rem; text-transform:uppercase; letter-spacing:.8px; }
.kpi .value { font-size:2.2rem; font-weight:700; line-height:1.15; margin-top:4px; }
.kpi .sub { color:#8b9ab8; font-size:.8rem; margin-top:2px; }
.panel-title { color:#e6edf7; font-weight:600; font-size:1.02rem; margin:4px 0 2px 2px; }
.panel-sub { color:#8b9ab8; font-size:.82rem; margin:0 0 4px 2px; }
table.log { width:100%; border-collapse:collapse; font-size:.88rem; }
table.log th { text-align:left; color:#8b9ab8; font-weight:500; padding:10px 12px; border-bottom:1px solid #1f2a44; text-transform:uppercase; font-size:.74rem; letter-spacing:.7px; }
table.log td { padding:10px 12px; border-bottom:1px solid #16213a; color:#e6edf7; }
table.log tr:hover td { background:#14203a; }
.badge { padding:3px 11px; border-radius:999px; font-size:.78rem; font-weight:600; }
.riskbar { width:90px; height:7px; background:#1f2a44; border-radius:99px; display:inline-block; vertical-align:middle; margin-right:8px; overflow:hidden; }
.riskbar i { display:block; height:100%; border-radius:99px; }
.wait { background:#111a2e; border:1px dashed #2a3a5e; border-radius:14px; padding:40px; text-align:center; color:#8b9ab8; }
</style>
""", unsafe_allow_html=True)

auto = st.sidebar.checkbox("Auto-refresh (3 s)", value=True)
limit = st.sidebar.slider("Windows to analyse", 50, 1000, 300)
st.sidebar.markdown("---")
st.sidebar.markdown("**How to read it**\n\n🟢 under 40% - allowed\n\n🟠 40-70% - domain restricted\n\n🔴 70%+ - channel blocked")


def load(n):
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        df = pd.read_sql_query("SELECT * FROM detections ORDER BY id DESC LIMIT ?", con, params=(n,))
        con.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_site_results():
    """All detector windows that belong to our 10 websites (their own domain or their C2 domain)."""
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    domains = [d for site in SITES for d in (site["domain"], site["c2"]) if d]
    try:
        con = sqlite3.connect(DB_PATH, timeout=10)
        out = pd.read_sql_query(
            "SELECT domain, prob, action FROM detections WHERE domain IN (%s) ORDER BY id DESC LIMIT 5000"
            % ",".join("?" * len(domains)), con, params=domains)
        con.close()
        return out
    except Exception:
        return pd.DataFrame()


def load_site_stats():
    """Leak statistics written by the two web-server containers."""
    out = {}
    for group in ("normal", "hacked"):
        try:
            with open(os.path.join(DATA_DIR, f"site_stats_{group}.json")) as f:
                out.update(json.load(f))
        except Exception:
            pass
    return out


def site_card(site, rows, stats):
    windows = len(rows)
    peak = float(rows["prob"].max()) * 100 if windows else 0.0
    flagged = bool((rows["action"] != "ALLOW").any()) if windows else False
    if not windows:
        verdict, col, mark = "Waiting for visit", MUTED, ""
    elif flagged:
        verdict, col = "COMPROMISED", RED
        mark = "&#10003; correct" if site["hacked"] else "&#10007; false alarm"
    else:
        verdict, col = "CLEAN", GREEN
        mark = "&#10007; missed" if site["hacked"] else "&#10003; correct"
    st_ = stats.get(site["id"], {})
    if site["hacked"] and st_:
        extra = f'Leaked {st_.get("bytes_leaked", 0)} B &middot; blocked {st_.get("bytes_blocked", 0)} B'
    elif st_:
        extra = f'{st_.get("visits", 0)} visits'
    else:
        extra = "&nbsp;"
    html = (f'<div class="kpi" style="border-top:3px solid {col};padding:14px 14px">'
            f'<div style="font-size:1.5rem">{site["emoji"]}</div>'
            f'<div style="font-weight:700;font-size:.98rem">{site["name"]}</div>'
            f'<div class="sub" style="margin-bottom:8px">{site["domain"]}</div>'
            f'<span class="badge" style="background:{col}22;color:{col};border:1px solid {col}55">{verdict}</span>'
            f'<div class="sub" style="margin-top:8px">We built it as: <b style="color:#e6edf7">'
            f'{"Hacked" if site["hacked"] else "Normal"}</b> {mark}</div>'
            f'<div class="sub">Peak risk {peak:.0f}% &middot; {windows} windows</div>'
            f'<div class="sub">{extra}</div></div>')
    return html, windows, (flagged == site["hacked"]) if windows else None


def kpi(label, value, sub, color):
    return (f'<div class="kpi" style="border-top:3px solid {color}"><div class="label">{label}</div>'
            f'<div class="value" style="color:{color}">{value}</div><div class="sub">{sub}</div></div>')


def style_fig(fig, height):
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      height=height, margin=dict(l=10, r=10, t=10, b=10),
                      font=dict(color=TEXT), legend=dict(orientation="h", y=-0.2, x=0))
    fig.update_xaxes(gridcolor="#1a2640", zeroline=False)
    fig.update_yaxes(gridcolor="#1a2640", zeroline=False)
    return fig


df = load(limit)
now = datetime.now().strftime("%H:%M:%S")
st.markdown(f"""<div class="hero"><div><h1>🛡️ DNS Tunneling Defense</h1>
<p>Real-time detection and automatic response to data exfiltration over DNS</p></div>
<div class="live"><span class="dot"></span>LIVE &nbsp;·&nbsp; {now}</div></div>""", unsafe_allow_html=True)

if df.empty:
    st.markdown('<div class="wait">⏳ Waiting for data...<br><small>Make sure the detector and victim containers are running.</small></div>',
                unsafe_allow_html=True)
else:
    df["ts"] = pd.to_datetime(df["ts"])
    df["risk"] = (df["prob"] * 100).round(1)
    blocked = open(BLOCKFILE).read().split() if os.path.exists(BLOCKFILE) else []
    latest = df.iloc[0]
    flagged = df[df["action"] != "ALLOW"]
    allowed = df[df["action"] == "ALLOW"]
    rate = 100 * len(flagged) / len(df)

    # ---- status banner ----
    if blocked:
        st.markdown(f'<div class="banner bad"><div class="icon">🚨</div><div><div class="big">Attack contained - '
                    f'blocked: {", ".join(blocked)}</div><div class="small">DNS tunneling traffic detected. '
                    f'The domain is being refused and the source host is firewalled.</div></div></div>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<div class="banner ok"><div class="icon">✅</div><div><div class="big">All clear - no active blocks</div>'
                    '<div class="small">DNS traffic looks normal. The detector is scoring every 5-second window.</div></div></div>',
                    unsafe_allow_html=True)

    # ---- KPI cards ----
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(kpi("Windows analysed", len(df), "5-second traffic windows", BLUE), unsafe_allow_html=True)
    c2.markdown(kpi("Normal (allowed)", len(allowed), f"{100 - rate:.1f}% of traffic", GREEN), unsafe_allow_html=True)
    c3.markdown(kpi("Tunnel detections", len(flagged), f"{rate:.1f}% of traffic", RED if len(flagged) else MUTED),
                unsafe_allow_html=True)
    c4.markdown(kpi("Domains blocked now", len(blocked), "active sinkholes", AMBER if blocked else MUTED),
                unsafe_allow_html=True)
    st.write("")

    # ---- website security check ----
    site_res, site_stat = load_site_results(), load_site_stats()
    cards, checked, correct = {}, 0, 0
    for site_ in SITES:
        rows_ = site_res[site_res["domain"].isin([site_["domain"], site_["c2"]])] if len(site_res) else site_res
        cards[site_["id"]], n_win, ok_ = site_card(site_, rows_, site_stat)
        if n_win:
            checked += 1
            correct += 1 if ok_ else 0
    summary = (f'<b style="color:{GREEN if checked and correct == checked else AMBER}">{correct} of {checked}</b> '
               f'visited websites classified correctly' if checked else "no website has been visited yet")
    st.markdown('<div class="panel-title">&#127760; Website security check &mdash; 10 lab websites</div>'
                f'<div class="panel-sub">Detector verdict for each website (5 normal, 5 hacked) &middot; {summary}</div>',
                unsafe_allow_html=True)
    for group_hacked in (False, True):
        cols_ = st.columns(5)
        for col_, site_ in zip(cols_, [x for x in SITES if x["hacked"] == group_hacked]):
            col_.markdown(cards[site_["id"]], unsafe_allow_html=True)
        st.write("")

    # ---- timeline + gauge ----
    left, right = st.columns([2.4, 1])
    with left:
        st.markdown('<div class="panel-title">Tunnel probability over time</div>'
                    '<div class="panel-sub">Each dot is one 5-second window. Shaded zones show the response levels.</div>',
                    unsafe_allow_html=True)
        d = df.sort_values("ts")
        fig = go.Figure()
        fig.add_hrect(y0=0, y1=40, fillcolor=GREEN, opacity=0.06, line_width=0)
        fig.add_hrect(y0=40, y1=70, fillcolor=AMBER, opacity=0.08, line_width=0)
        fig.add_hrect(y0=70, y1=100, fillcolor=RED, opacity=0.10, line_width=0)
        fig.add_trace(go.Scatter(x=d["ts"], y=d["risk"], mode="lines", line=dict(color="#3b4a6b", width=1),
                                 hoverinfo="skip", showlegend=False))
        for act, col in ACTION_COLOR.items():
            s = d[d["action"] == act]
            if len(s):
                fig.add_trace(go.Scatter(
                    x=s["ts"], y=s["risk"], mode="markers", name=ACTION_LABEL[act],
                    marker=dict(color=col, size=10 if act != "ALLOW" else 8, line=dict(color="#0b1220", width=1)),
                    customdata=s[["domain", "n_queries", "avg_entropy", "unique_subs"]],
                    hovertemplate="<b>%{customdata[0]}</b><br>Risk: %{y}%<br>Queries: %{customdata[1]}"
                                  "<br>Entropy: %{customdata[2]:.2f}<br>Unique names: %{customdata[3]}<extra></extra>"))
        fig.update_yaxes(range=[0, 105], title="Tunnel probability (%)")
        st.plotly_chart(style_fig(fig, 340), width="stretch")
    with right:
        st.markdown('<div class="panel-title">Latest window risk</div>'
                    f'<div class="panel-sub">{latest["domain"]} · {latest["ts"].strftime("%H:%M:%S")}</div>',
                    unsafe_allow_html=True)
        g = go.Figure(go.Indicator(
            mode="gauge+number", value=float(latest["risk"]), number=dict(suffix="%", font=dict(color=TEXT, size=44)),
            gauge=dict(axis=dict(range=[0, 100], tickcolor=MUTED), bar=dict(color=ACTION_COLOR.get(latest["action"], BLUE)),
                       bgcolor="#0e1627", borderwidth=0,
                       steps=[dict(range=[0, 40], color="#0f2a1c"), dict(range=[40, 70], color="#2d230d"),
                              dict(range=[70, 100], color="#35121a")])))
        st.plotly_chart(style_fig(g, 250), width="stretch")
        col = ACTION_COLOR.get(latest["action"], BLUE)
        st.markdown(f'<div style="text-align:center"><span class="badge" style="background:{col}22;color:{col};'
                    f'border:1px solid {col}55">{ACTION_LABEL.get(latest["action"], latest["action"])}</span></div>',
                    unsafe_allow_html=True)

    st.write("")
    # ---- donut + entropy comparison + busiest domains ----
    a, b, c = st.columns(3)
    with a:
        st.markdown('<div class="panel-title">Actions taken</div><div class="panel-sub">Share of all decisions</div>',
                    unsafe_allow_html=True)
        cnt = df["action"].value_counts()
        pie = go.Figure(go.Pie(labels=[ACTION_LABEL[k] for k in cnt.index], values=cnt.values, hole=0.62,
                               marker=dict(colors=[ACTION_COLOR[k] for k in cnt.index], line=dict(color="#0b1220", width=2)),
                               textinfo="percent"))
        st.plotly_chart(style_fig(pie, 280), width="stretch")
    with b:
        st.markdown('<div class="panel-title">Why it works: name randomness</div>'
                    '<div class="panel-sub">Average entropy by decision - tunnels look random</div>', unsafe_allow_html=True)
        ent = df.groupby("action")["avg_entropy"].mean().reindex(list(ACTION_COLOR)).dropna()
        bar = go.Figure(go.Bar(x=[ACTION_LABEL[k] for k in ent.index], y=ent.values.round(2),
                               marker_color=[ACTION_COLOR[k] for k in ent.index], text=ent.values.round(2),
                               textposition="outside"))
        bar.update_yaxes(title="avg entropy", range=[0, max(5, float(ent.max()) + 0.8)])
        st.plotly_chart(style_fig(bar, 280), width="stretch")
    with c:
        st.markdown('<div class="panel-title">Busiest domains</div><div class="panel-sub">Total queries seen</div>',
                    unsafe_allow_html=True)
        top = df.groupby("domain").agg(q=("n_queries", "sum"), risk=("risk", "max")).sort_values("q").tail(7)
        tb = go.Figure(go.Bar(y=top.index, x=top["q"], orientation="h",
                              marker_color=[RED if r >= 70 else AMBER if r >= 40 else BLUE for r in top["risk"]]))
        tb.update_xaxes(title="queries")
        st.plotly_chart(style_fig(tb, 280), width="stretch")

    # ---- explainable alerts ----
    st.markdown('<div class="panel-title">🔍 Why was it flagged? (Explainable AI)</div>'
                '<div class="panel-sub">Exact Shapley values: how many probability points each clue added '
                'compared with a typical normal window</div>', unsafe_allow_html=True)
    if "explanation" in df.columns:
        ex_df = df[(df["action"] != "ALLOW") & df["explanation"].notna()].head(20)
    else:
        ex_df = df.iloc[0:0]
    if ex_df.empty:
        st.markdown('<div class="wait">No explained alerts yet.<br><small>Run the attack to see exactly '
                    'why the system flags it.</small></div>', unsafe_allow_html=True)
    else:
        labels = [f'#{r["id"]}  ·  {r["ts"].strftime("%H:%M:%S")}  ·  {r["domain"]}  ·  {r["risk"]}%  ·  '
                  f'{ACTION_LABEL.get(r["action"], r["action"])}' for _, r in ex_df.iterrows()]
        pick = st.selectbox("Choose an alert to explain", labels, index=0, key="xai_pick")
        row = ex_df.iloc[labels.index(pick)]
        ex = json.loads(row["explanation"])
        top = ex.get("top", [])
        el, er = st.columns([1.5, 1])
        with el:
            if top:
                t_sorted = sorted(top, key=lambda t: t["impact"])
                xb = go.Figure(go.Bar(
                    y=[t["label"] for t in t_sorted], x=[t["impact"] for t in t_sorted], orientation="h",
                    marker_color=RED, text=[f'+{t["impact"]:.0f} pts' for t in t_sorted], textposition="outside"))
                xb.update_xaxes(title="probability points added", range=[0, max(t["impact"] for t in top) * 1.3])
                st.plotly_chart(style_fig(xb, 300), width="stretch")
        with er:
            col = ACTION_COLOR.get(row["action"], BLUE)
            items = "".join(
                f'<div style="margin:7px 0"><b>{t["label"]}</b><br>'
                f'<span style="color:#8b9ab8">this window</span> {t["value"]:g} &nbsp;vs&nbsp; '
                f'<span style="color:#8b9ab8">normal</span> {t["normal"]:g} &nbsp;'
                f'<span style="color:{RED};font-weight:700">+{t["impact"]:.0f} pts</span></div>' for t in top[:4])
            main = ", ".join(t["label"] for t in top[:3])
            st.markdown(
                f'<div style="background:#111a2e;border:1px solid #1f2a44;border-radius:14px;padding:16px 18px">'
                f'<div style="color:#8b9ab8;font-size:.82rem;text-transform:uppercase;letter-spacing:.8px">Verdict</div>'
                f'<div style="font-size:1.05rem;margin:4px 0 10px 0">A typical normal window scores about '
                f'<b>{ex.get("base_prob", 0)}%</b>. This one scored <b style="color:{col}">{row["risk"]}%</b>.</div>'
                f'<div style="color:#8b9ab8;font-size:.82rem;text-transform:uppercase;letter-spacing:.8px">Main reasons</div>'
                f'{items}'
                f'<div style="margin-top:10px;font-size:.9rem;color:#e6edf7">Flagged mainly because of: {main}.</div></div>',
                unsafe_allow_html=True)

    # ---- decisions table ----
    st.markdown('<div class="panel-title">Latest decisions</div>'
                '<div class="panel-sub">Newest first · risk bar shows the model\'s tunnel probability</div>',
                unsafe_allow_html=True)
    rows = ""
    for _, r in df.head(15).iterrows():
        col = ACTION_COLOR.get(r["action"], BLUE)
        rows += (f'<tr><td>{r["ts"].strftime("%H:%M:%S")}</td><td>{r["src"]}</td><td><b>{r["domain"]}</b></td>'
                 f'<td>{int(r["n_queries"])}</td><td>{r["avg_entropy"]:.2f}</td><td>{int(r["unique_subs"])}</td>'
                 f'<td><span class="riskbar"><i style="width:{r["risk"]}%;background:{col}"></i></span>{r["risk"]}%</td>'
                 f'<td><span class="badge" style="background:{col}22;color:{col};border:1px solid {col}55">'
                 f'{ACTION_LABEL.get(r["action"], r["action"])}</span></td></tr>')
    st.markdown('<div style="background:#111a2e;border:1px solid #1f2a44;border-radius:14px;padding:6px 8px;overflow-x:auto">'
                '<table class="log"><thead><tr><th>Time</th><th>Source</th><th>Domain</th><th>Queries</th><th>Entropy</th>'
                f'<th>Unique names</th><th>Risk</th><th>Action</th></tr></thead><tbody>{rows}</tbody></table></div>',
                unsafe_allow_html=True)

if auto:
    time.sleep(3)
    st.rerun()
