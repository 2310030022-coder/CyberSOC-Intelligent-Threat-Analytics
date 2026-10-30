# 🛡️ SentinelSOC — Threat Detection & MITRE ATT&CK Mapping (V2)

A **rule-based SOC threat-analysis dashboard** built with **Python, Streamlit, Pandas and Plotly**. It analyzes synthetic or user-provided SIEM-style CSV logs, identifies candidate suspicious events, maps them to MITRE ATT&CK techniques, and produces an analyst-readable report.

> **Scope:** Training/portfolio prototype. Not a trained AI model, production SIEM, or real-time monitoring system. Detection results are **candidates requiring human review**, not confirmed incidents.

## Features

- Upload a custom `.csv` file (up to 5 MB and 10,000 events), or use the built-in example.
- Apply **13 transparent regex detection rules** (PowerShell, possible credential access, suspicious authentication, phishing, HTTP beaconing, unexpected RDP, privilege changes, shell use, scheduled tasks, log clearing, and more).
- Map matched indicators to **MITRE ATT&CK techniques and tactics** with links to MITRE's official reference.
- Prioritize matches as Critical / High / Medium using **illustrative priority scores**, not likelihood estimates.
- Interactive filters by severity, host, ATT&CK technique and free-text search.
- Show severity charts, technique counts, event timeline, host distribution, and event-specific investigation guidance.
- Download candidate findings as CSV, an analyst-readable security report, and the rules as JSON.
- Includes **12 automated unit tests** for sample outputs, false-positive controls, input validation, multiple matches, reporting and CSV export safety.

## Project screenshots

To add screenshots after deployment, capture the dashboard and upload images to your repository (e.g. `dashboard.png`). Avoid screenshots containing sensitive data.

## Files

| File | Purpose |
|---|---|
| `app.py` | Streamlit web dashboard and CSV uploader |
| `soc_engine.py` | Reusable detection, validation, reporting and safe CSV export |
| `detection_rules.json` | Readable rule definitions, severity and MITRE mapping |
| `sample_logs.csv` | Synthetic 12-event practice dataset |
| `test_soc_engine.py` | Twelve automated unit tests |
| `requirements.txt` | App dependencies |

The original course notebook `SOC_Threat_Detection_MITRE_ATTACK.ipynb` can remain in this same GitHub repository as the **Version 1 Colab exercise**. The new `app.py` is the entry point for the Version 2 interactive application.

## Run on your computer

Use Python 3.10+:

```bash
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL shown in the terminal. The default sample loads automatically. To use your own data, choose **Upload your SIEM CSV** in the sidebar.

### CSV format

Required headers (case-insensitive):

```csv
event_id,timestamp,source,host,user,event,details
EVT100,2026-10-30 13:00:00,Endpoint,ws-01,analyst,PowerShell Execution,Suspicious powershell -enc observed
EVT101,2026-10-30 13:05:00,Backup,backup-01,service,Backup Success,Scheduled backup completed normally
```

- `event_id` is required and must be unique within the upload.
- `event` is required. Blank details are allowed.
- Timestamp values are displayed as provided; recognizable timestamps are used in the timeline.
- Input is processed in memory by the app; it is not uploaded to a model/API or permanently stored by project code. **Do not upload real sensitive logs to an untrusted public deployment.**

## Run tests

```bash
python -m unittest -v test_soc_engine.py
```

With the included synthetic dataset, the expected results are:

| Metric | Expected |
|---|---:|
| Input events | 12 |
| Candidate alerts | 10 |
| Events without alerts | 2 |
| Automated unit tests | 12 passing |

These are *lab validation counts*, not real-world detection accuracy or false-positive rates.

## Publish to Streamlit Community Cloud

1. Commit these project files to your **existing SOC project repository** on GitHub. Keep the files in the repository root, alongside `requirements.txt`.
2. Go to [share.streamlit.io](https://share.streamlit.io/) and sign in with GitHub.
3. Click **Create app** → **Yup, I have an app**.
4. Select your GitHub repository, branch `main`, and entrypoint `app.py`.
5. Click **Deploy**. After success, copy the assigned `*.streamlit.app` URL and add it to the repository's **About → Website** field and your resume.

## How detections work

For each event, the engine searches the `event` and `details` fields for the documented regex patterns. Each matching rule creates a candidate alert with a severity priority, MITRE ID, explanation and recommended analyst next steps. Multiple rules may match one event. A non-match does **not** prove safety.

**MITRE ATT&CK references:** [Official ATT&CK](https://attack.mitre.org/) · [MITRE CTI STIX dataset](https://github.com/mitre/cti). MITRE ATT&CK is a trademark of The MITRE Corporation. This independent lab is not endorsed by MITRE.

## Responsible use and limitations

- Use only synthetic logs or data you have permission to analyze.
- Rules are educational heuristics and may produce false positives or miss malicious activity.
- This demo has no authentication, continuous ingestion, commercial SIEM integration, trained AI model, or incident-response automation.
- Downloaded CSV output escapes leading spreadsheet formula characters to reduce formula-injection risk in spreadsheet applications.
- Verify ATT&CK mappings and severity judgments during actual SOC triage.

## Resume description

**SOC Threat Detection & MITRE ATT&CK Mapping — Python, Streamlit, Pandas, Plotly**

- Built a rule-based SOC analytics dashboard supporting custom SIEM CSV uploads, ATT&CK technique mapping and severity-based alert triage.
- Implemented 13 explainable detection rules with drill-down evidence, filtering, host/event timelines and downloadable security reports.
- Validated the detection engine with 12 automated tests and a synthetic 12-event dataset (10 expected candidate alerts).
