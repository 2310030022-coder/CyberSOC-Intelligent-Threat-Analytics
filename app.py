"""Interactive SOC lab dashboard. Entry point: streamlit run app.py"""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from soc_engine import detect, export_csv, load_rules, report_text, validate_logs

ROOT = Path(__file__).parent
st.set_page_config(page_title="SentinelSOC | Threat Analytics", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.stApp {background: #f6f8fc; color: #14223a;}
.block-container {padding-top: 1.6rem; max-width: 1350px;}
h1, h2, h3 {letter-spacing: -0.025em;}
.hero {background:linear-gradient(115deg,#101d3a 0%,#193e6b 58%,#126a78 100%);
       color:white; padding:28px 32px; border-radius:16px; margin-bottom:17px;}
.hero h1 {color:white; margin:0; font-size:2.1rem;}
.hero p {color:#d5e9f0; margin:9px 0 0; font-size:1.03rem;}
.tag {background:#d3f4ec; color:#056954; border-radius:6px; padding:5px 9px;
      font-weight:700; font-size:0.8rem; display:inline-block; margin-bottom:12px;}
[data-testid="stMetric"] {background: white; border:1px solid #e1e7ee; border-radius:12px; padding:12px 16px;}
[data-testid="stMetricValue"] {color:#173455;}
[data-testid="stSidebar"] {background:#edf3f9;}
.footer {font-size:0.83rem; color:#526784; margin-top:26px; border-top:1px solid #dce4ee; padding-top:13px;}
</style>
""", unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def sample_data():
    return pd.read_csv(ROOT / "sample_logs.csv", dtype=str).fillna("")

@st.cache_data(show_spinner=False)
def get_rules():
    return load_rules(ROOT / "detection_rules.json")

st.markdown('''<div class="hero"><div class="tag">SOC ANALYTICS · DEMONSTRATION LAB</div>
<h1>🛡️ SentinelSOC — Threat Detection Console</h1>
<p>SIEM log triage · MITRE ATT&amp;CK mapping · rule-based findings · analyst-ready reports</p></div>''',
unsafe_allow_html=True)

with st.sidebar:
    st.header("Data source")
    uploaded = st.file_uploader("Upload your SIEM CSV", type="csv", help="CSV up to 5 MB; maximum 10,000 events. Files are processed in-memory.")
    st.caption("Required fields: event_id, timestamp, source, host, user, event, details")
    st.divider()
    st.header("How it works")
    st.markdown("1. Load a CSV or use the included sample.\n2. Apply documented regex detection rules.\n3. Investigate and export candidate findings.")
    st.info("No real-time monitoring or machine-learning model. Example logs are synthetic. Alert matches need human review.")

try:
    if uploaded is None:
        logs = validate_logs(sample_data())
        dataset_label = "Synthetic demo dataset"
    else:
        if uploaded.size > 5 * 1024 * 1024:
            st.error("CSV file is over 5 MB. Please upload a smaller file.")
            st.stop()
        logs = validate_logs(pd.read_csv(BytesIO(uploaded.getvalue()), dtype=str, keep_default_na=False))
        dataset_label = "Uploaded CSV"
except (ValueError, pd.errors.ParserError, UnicodeDecodeError, KeyError) as exc:
    st.error(f"Unable to load events: {exc}")
    st.caption("Download sample_logs.csv from the repository to see the expected format.")
    st.stop()

rules = get_rules()
findings = detect(logs, rules)
alerted_events = findings.event_id.nunique() if not findings.empty else 0

st.caption(f"Source: {dataset_label} · {len(rules)} detection rules · Offline processing · No external log upload")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", f"{len(logs):,}")
m2.metric("Candidate alerts", f"{len(findings):,}")
m3.metric("Events flagged", f"{alerted_events:,}")
m4.metric("ATT&CK techniques", f"{findings.mitre_id.nunique() if not findings.empty else 0}")

st.subheader("Investigate alerts")
if findings.empty:
    st.success("No indicators matched the current rules. This does not guarantee that the data is free of threats.")
    filtered = findings
else:
    f1, f2, f3 = st.columns([1, 1.4, 1.6])
    severities = f1.multiselect("Severity", ["Critical", "High", "Medium", "Low"], default=sorted(findings.severity.unique(), key=lambda x: ["Critical", "High", "Medium", "Low"].index(x)))
    hosts = f2.multiselect("Affected hosts", sorted(findings.host.unique()), default=sorted(findings.host.unique()))
    techniques = f3.multiselect("MITRE techniques", sorted(findings.mitre_id.unique()), default=sorted(findings.mitre_id.unique()))
    keyword = st.text_input("Search alerts (rule, user, event, evidence)", placeholder="e.g. PowerShell, LSASS, web-01")
    filtered = findings[
        findings.severity.isin(severities)
        & findings.host.isin(hosts)
        & findings.mitre_id.isin(techniques)
    ].copy()
    if keyword.strip():
        q = keyword.strip()
        matching = filtered[["detection", "event", "user", "evidence", "host"]].apply(
            lambda col: col.str.contains(q, case=False, regex=False, na=False)
        ).any(axis=1)
        filtered = filtered[matching]
    st.caption(f"Showing {len(filtered):,} of {len(findings):,} candidate alerts")
    display_cols = ["event_id", "timestamp", "severity", "score", "host", "user", "detection", "mitre_id", "tactic"]
    st.dataframe(filtered[display_cols], use_container_width=True, hide_index=True)

st.subheader("Threat intelligence overview")
left, right = st.columns(2)
with left:
    if filtered.empty:
        st.info("No alerts in the current filter selection.")
    else:
        sev = filtered.severity.value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0).reset_index()
        sev.columns = ["Severity", "Alerts"]
        fig = px.bar(sev, x="Severity", y="Alerts", color="Severity", text="Alerts",
                     title="Alerts by severity", color_discrete_map={"Critical":"#bd3b52", "High":"#ea8050", "Medium":"#e4b344", "Low":"#378baf"})
        fig.update_layout(template="plotly_white", showlegend=False, margin=dict(t=45,b=25,l=15,r=15), height=330)
        st.plotly_chart(fig, use_container_width=True)
with right:
    if filtered.empty:
        st.info("No technique counts in this selection.")
    else:
        techniques_df = filtered.groupby(["mitre_id", "technique"], as_index=False).size().rename(columns={"size": "Alerts"})
        fig = px.bar(techniques_df.sort_values("Alerts", ascending=False), x="mitre_id", y="Alerts", color="Alerts",
                     hover_data=["technique"], title="MITRE ATT&CK technique matches", color_continuous_scale="Teal")
        fig.update_layout(template="plotly_white", coloraxis_showscale=False, margin=dict(t=45,b=25,l=15,r=15), height=330)
        st.plotly_chart(fig, use_container_width=True)

with st.expander("Event timeline and host distribution", expanded=True):
    tl, hc = st.columns(2)
    with tl:
        if not filtered.empty:
            timeline = filtered.copy()
            timeline["parsed_time"] = pd.to_datetime(timeline["timestamp"], errors="coerce", utc=True)
            timeline = timeline.dropna(subset=["parsed_time"])
            if not timeline.empty:
                fig = px.scatter(timeline, x="parsed_time", y="host", color="severity", hover_data=["detection", "mitre_id", "event_id"],
                                 title="When did flagged events occur?", color_discrete_map={"Critical":"#bd3b52", "High":"#ea8050", "Medium":"#d2a02e", "Low":"#378baf"})
                fig.update_layout(template="plotly_white", height=350, margin=dict(t=50,b=20,l=10,r=10))
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No valid event timestamps to plot. Use ISO-style timestamps to see a timeline.")
        else:
            st.info("No flagged events to plot.")
    with hc:
        if not filtered.empty:
            hostcounts = filtered.host.value_counts().head(12).reset_index()
            hostcounts.columns = ["Host", "Alerts"]
            fig = px.bar(hostcounts, x="Alerts", y="Host", orientation="h", title="Hosts with candidate alerts", color_discrete_sequence=["#117f87"])
            fig.update_layout(template="plotly_white", height=350, margin=dict(t=50,b=20,l=10,r=10), yaxis={"categoryorder":"total ascending"})
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No hosts with candidate alerts.")

st.subheader("Evidence and investigation guidance")
if filtered.empty:
    st.caption("Change filters or upload a different log file to inspect alerts.")
else:
    labels = [f"{r.event_id} · {r.detection} · {r.host}" for r in filtered.itertuples()]
    choice = st.selectbox("Choose a candidate finding", range(len(labels)), format_func=lambda i: labels[i])
    item = filtered.iloc[choice]
    a, b = st.columns([1, 2])
    with a:
        st.markdown(f"**Rule:** {item['rule_id']}")
        st.markdown(f"**Severity:** {item['severity']} (priority {item['score']}/100)")
        st.markdown(f"**ATT&CK:** [{item['mitre_id']}]({item['mitre_url']})")
        st.markdown(f"**Tactic:** {item['tactic']}")
        st.markdown(f"**Status:** {item['status']}")
    with b:
        st.markdown("**Why this was flagged**")
        st.write(item["explanation"])
        st.markdown("**Observed event details**")
        st.code(str(item["evidence"]), language=None)
        st.markdown("**Suggested analyst next step**")
        st.write(item["recommendation"])

st.subheader("Download analysis")
d1, d2, d3 = st.columns(3)
d1.download_button("⬇️ Findings CSV", export_csv(filtered), "threat_findings.csv", mime="text/csv", use_container_width=True)
d2.download_button("⬇️ Security report", report_text(logs, findings), "security_report.txt", mime="text/plain", use_container_width=True)
d3.download_button("⬇️ Detection rules JSON", (ROOT / "detection_rules.json").read_bytes(), "detection_rules.json", mime="application/json", use_container_width=True)
with st.expander("Raw input events"):
    st.dataframe(logs, use_container_width=True, hide_index=True)
st.markdown('<div class="footer">Built for an authorized, synthetic SOC lab. Rule matches are investigative leads only. ATT&amp;CK is a trademark of The MITRE Corporation. This project is not affiliated with MITRE.</div>', unsafe_allow_html=True)
