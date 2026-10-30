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
.stApp { background:#f5f8fe; color:#152c4d; }
.block-container { max-width:1420px; padding-top:1.2rem; padding-bottom:3rem; }
h1,h2,h3 { letter-spacing:-0.025em; }
.hero { background:linear-gradient(108deg,#10274c,#174d7a 62%,#087e89);
 color:white; padding:35px 37px; border-radius:19px; margin-bottom:20px;
 box-shadow:0 10px 28px rgba(22,50,95,.13); }
.hero h1 {color:#fff; font-size:clamp(2.1rem,3.2vw,3rem); margin:3px 0 9px; line-height:1.15;}
.hero p {font-size:1.16rem; color:#e5f7fa; margin:0;}
.eyebrow {display:inline-block; background:rgba(219,255,250,.19); color:#f4ffff;
 border:1px solid #62b9bd; border-radius:25px; padding:6px 13px; font-weight:800;}
.title-blue {font-size:2rem; font-weight:850; color:#173455; margin:4px 0 8px; line-height:1.15;}
.muted-big {font-size:1.13rem; color:#465e78; margin-bottom:16px;}
.kicker {color:#077e8b; font-size:.92rem; letter-spacing:.1em; font-weight:850; text-transform:uppercase;}
.steps {display:grid; grid-template-columns:repeat(3,1fr); gap:13px; margin:15px 0 21px;}
.step {background:#fff; border:1px solid #dbe7f6; border-radius:15px;
 padding:18px; min-height:125px;}
.step b {font-size:1.11rem; color:#133254;}
.step p {font-size:1rem; color:#47617b; margin:12px 0 0; line-height:1.42;}
.num {display:inline-block; padding:5px 10px; background:#d9ebff; color:#116da9;
 border-radius:50px; font-weight:900; margin-right:7px;}
.guide {background:linear-gradient(125deg,#ffffff,#e9f9f9); border:1px solid #c9e1e7;
 border-radius:14px; padding:19px;}
.guide h3 {color:#173f58; margin:0 0 9px; font-size:1.42rem;}
.guide p {color:#476178; font-size:1.02rem; margin:0;}
.fields {display:grid; grid-template-columns:repeat(2,1fr); gap:9px; margin-top:13px;}
.field {background:white; border:1px solid #d3e4ef; border-radius:10px; padding:11px;}
.field b {display:block; color:#06718b; font-size:1.08rem; font-family:monospace;}
.field span {font-size:.95rem; color:#4c6078;}
.tip {background:#eaf4ff; border-left:5px solid #3986d2; padding:14px 17px;
 border-radius:10px; font-size:1.01rem; color:#173858; margin:13px 0;}
.active-demo {background:#fff5e2; border:1px solid #f4d79a; border-radius:12px;
 padding:14px 17px; color:#6f4b16; font-size:1.02rem; margin:13px 0 17px;}
.active-upload {background:#e4faf2; border:1px solid #9bdcbf; border-radius:12px;
 padding:14px 17px; color:#155b45; font-size:1.02rem; margin:13px 0 17px;}
[data-testid="stFileUploader"] section {border:2px dashed #2488ae !important;
 background:#effaff !important; padding:23px !important; border-radius:13px !important; min-height:132px;}
[data-testid="stFileUploader"] label {font-weight:750 !important; font-size:1.14rem !important;}
[data-testid="stMetric"] {background:white;border:1px solid #dbe6f5;border-radius:12px;padding:15px;}
[data-testid="stMetricValue"] {color:#173455;font-size:2rem !important;}
[data-testid="stSidebar"] {background:#edf4fa;}
.footer {font-size:.9rem;color:#516782;margin-top:27px;border-top:1px solid #dce4ee;padding-top:14px;}
@media(max-width:850px){.hero{padding:24px 18px}.steps,.fields{grid-template-columns:1fr}.title-blue{font-size:1.6rem}}
</style>
""", unsafe_allow_html=True)

@st.cache_data(show_spinner=False)
def sample_data():
    return pd.read_csv(ROOT / "sample_logs.csv", dtype=str).fillna("")

@st.cache_data(show_spinner=False)
def get_rules():
    return load_rules(ROOT / "detection_rules.json")

st.markdown('''<div class="hero"><span class="eyebrow">CYBERSOC · SOC ANALYST LAB</span>
<h1>🛡️ CyberSOC — Security Threat Detection</h1>
<p>Upload security event logs, detect suspicious patterns, map findings to MITRE ATT&amp;CK, and explore a complete SOC dashboard.</p></div>''', unsafe_allow_html=True)

st.markdown('''<div class="kicker">STEP 1 · START WITH YOUR INPUT</div>
<div class="title-blue">What should the user upload?</div>
<div class="muted-big">Upload a <b>CSV file containing SIEM / security event logs</b>. One row represents one event. You do <b>not</b> need to enter Python code, passwords, or an API key.</div>
<div class="steps">
<div class="step"><span class="num">1</span><b>Prepare security logs</b><p>Save the events as a CSV with the 7 required column names listed below.</p></div>
<div class="step"><span class="num">2</span><b>Upload CSV file</b><p>Use the large file upload box or try the downloadable sample data.</p></div>
<div class="step"><span class="num">3</span><b>Review threat findings</b><p>See severity ratings, MITRE ATT&amp;CK mappings, charts, and security reports.</p></div>
</div>''', unsafe_allow_html=True)

upload_area, schema_area = st.columns([1.05, .95], gap="large")
with upload_area:
    with st.container(border=True):
        st.markdown("## 📤 Upload Security Event Logs")
        st.markdown("**File type:** `.csv` &nbsp; · &nbsp; **Max file size:** 5 MB &nbsp; · &nbsp; **Maximum rows:** 10,000")
        uploaded = st.file_uploader(
            "Select your SIEM / security event CSV file",
            type=["csv"],
            help="Must contain event_id, timestamp, source, host, user, event, details. Do not upload confidential logs.",
            key="cybersoc_upload_csv",
        )
        st.download_button(
            "⬇ Download sample_logs.csv — example input",
            data=(ROOT / "sample_logs.csv").read_bytes(),
            file_name="sample_logs.csv", mime="text/csv",
            use_container_width=True,
        )
        st.caption("First time? Download the sample above and upload it here to see the results instantly.")
with schema_area:
    st.markdown('''<div class="guide"><h3>📋 7 required CSV columns</h3>
<p>Keep these header names in the first row of your CSV file.</p>
<div class="fields">
<div class="field"><b>event_id</b><span>Unique event ID, e.g. EVT001</span></div>
<div class="field"><b>timestamp</b><span>When it happened</span></div>
<div class="field"><b>source</b><span>Log type, e.g. Endpoint</span></div>
<div class="field"><b>host</b><span>Device name, e.g. ws-01</span></div>
<div class="field"><b>user</b><span>Account, e.g. alice</span></div>
<div class="field"><b>event</b><span>Event type, e.g. Failed Logins</span></div>
<div class="field"><b>details</b><span>Description, e.g. 15 failed logins</span></div>
</div></div>''', unsafe_allow_html=True)
    st.markdown('''<div class="tip"><b>Required:</b> <code>event_id</code> values must be unique and the <code>event</code> field cannot be blank. Use only synthetic or authorized, non-sensitive logs.</div>''', unsafe_allow_html=True)

st.markdown("### 👀 Preview: What an accepted CSV looks like")
st.write("Here are three example event rows. In Excel or Google Sheets, create the same seven columns and save the file as **CSV**.")
st.dataframe(sample_data().head(3), use_container_width=True, hide_index=True)

try:
    if uploaded is None:
        logs = validate_logs(sample_data())
        dataset_label = "Built-in sample dataset (demo mode)"
        st.markdown('''<div class="active-demo"><b>🧪 Sample mode:</b> No file has been uploaded. The dashboard uses 12 synthetic security events so you can explore the application. Upload your own CSV above to replace them.</div>''', unsafe_allow_html=True)
    else:
        if uploaded.size > 5 * 1024 * 1024:
            st.error("The CSV file exceeds 5 MB. Select a smaller CSV and try again.")
            st.stop()
        logs = validate_logs(pd.read_csv(BytesIO(uploaded.getvalue()), dtype=str, keep_default_na=False, encoding="utf-8-sig"))
        dataset_label = f"Uploaded CSV: {uploaded.name}"
        st.markdown('''<div class="active-upload"><b>✅ File accepted:</b> The uploaded security events passed validation and are being analyzed. Scroll down for your dashboard, alerts, and reports.</div>''', unsafe_allow_html=True)
except (ValueError, pd.errors.ParserError, UnicodeDecodeError, KeyError, pd.errors.EmptyDataError) as exc:
    st.error(f"CSV upload problem: {exc}")
    st.info("Download sample_logs.csv above and compare its first row to your file. Required: event_id, timestamp, source, host, user, event, details.")
    st.stop()

st.divider()
st.markdown('''<div class="kicker">STEP 2 · ANALYSIS RESULTS</div>
<div class="title-blue">Security Monitoring Dashboard</div>''', unsafe_allow_html=True)

with st.sidebar:
    st.header("CyberSOC")
    st.info("To upload your own security events, use the large **Upload Security Event Logs** panel at the top of this page.")
    st.markdown("**How it works**")
    st.markdown("1. Upload CSV (or try the sample).\n2. Run threat detection rules.\n3. Investigate mapped ATT&CK techniques.\n4. Download findings and reports.")
    st.warning("Demonstration only. This is a rule-based SOC prototype, not live monitoring or a trained AI model.")

rules = get_rules()
findings = detect(logs, rules)
alerted_events = findings.event_id.nunique() if not findings.empty else 0

st.caption(f"Source: {dataset_label} · {len(rules)} detection rules · Rule-based analysis · No external detection API")
m1, m2, m3, m4 = st.columns(4)
m1.metric("Events analyzed", f"{len(logs):,}")
m2.metric("Candidate alerts", f"{len(findings):,}")
m3.metric("Events flagged", f"{alerted_events:,}")
m4.metric("ATT&CK techniques", f"{findings.mitre_id.nunique() if not findings.empty else 0}")

st.subheader("🔎 Investigate alerts")
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

st.subheader("📊 Threat intelligence overview")
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

st.subheader("🧩 Evidence and investigation guidance")
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

st.subheader("📥 Download analysis")
d1, d2, d3 = st.columns(3)
d1.download_button("⬇️ Findings CSV", export_csv(filtered), "threat_findings.csv", mime="text/csv", use_container_width=True)
d2.download_button("⬇️ Security report", report_text(logs, findings), "security_report.txt", mime="text/plain", use_container_width=True)
d3.download_button("⬇️ Detection rules JSON", (ROOT / "detection_rules.json").read_bytes(), "detection_rules.json", mime="application/json", use_container_width=True)
with st.expander("Raw input events"):
    st.dataframe(logs, use_container_width=True, hide_index=True)
st.markdown('<div class="footer">Built for an authorized, synthetic SOC lab. Rule matches are investigative leads only. ATT&amp;CK is a trademark of The MITRE Corporation. This project is not affiliated with MITRE.</div>', unsafe_allow_html=True)
