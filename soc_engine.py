"""Offline, rule-based SIEM event screening and ATT&CK mapping.

No uploaded content is sent to an external service. Findings are *candidates*,
not confirmed compromises or measured ML predictions.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

import pandas as pd

REQUIRED_COLUMNS = ("event_id", "timestamp", "source", "host", "user", "event", "details")
SEVERITY_SCORES = {"Critical": 90, "High": 70, "Medium": 45, "Low": 20}
FINDING_COLUMNS = (
    "event_id", "timestamp", "source", "host", "user", "event", "rule_id",
    "detection", "severity", "score", "mitre_id", "technique",
    "tactic", "mitre_url", "matched_indicator", "evidence", "explanation",
    "recommendation", "status",
)


def load_rules(path: str | Path | None = None) -> list[dict]:
    rules_path = Path(path) if path else Path(__file__).with_name("detection_rules.json")
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    if not isinstance(rules, list) or not rules:
        raise ValueError("Detection rules must be a nonempty JSON list")
    seen = set()
    for rule in rules:
        required = {"id", "name", "pattern", "technique_id", "technique", "tactic", "severity", "explanation", "recommendation"}
        if not isinstance(rule, dict) or not required.issubset(rule):
            raise ValueError("A detection rule has missing fields")
        if rule["id"] in seen or rule["severity"] not in SEVERITY_SCORES:
            raise ValueError("Duplicate rule ID or unsupported severity")
        seen.add(rule["id"])
        re.compile(rule["pattern"], flags=re.IGNORECASE)
    return rules


def validate_logs(data: pd.DataFrame, *, max_rows: int = 10000) -> pd.DataFrame:
    if not isinstance(data, pd.DataFrame):
        raise ValueError("Upload a CSV table")
    normalized = [str(c).strip().lower().removeprefix("\ufeff") for c in data.columns]
    if len(set(normalized)) != len(normalized):
        raise ValueError("Duplicate column names after normalization")
    df = data.copy()
    df.columns = normalized
    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(missing))
    if len(df) == 0:
        raise ValueError("CSV contains no events")
    if len(df) > max_rows:
        raise ValueError(f"CSV exceeds {max_rows:,} events; split into smaller files")
    df = df.loc[:, REQUIRED_COLUMNS].fillna("").astype(str)
    for col in REQUIRED_COLUMNS:
        df[col] = df[col].str.strip()
    if df["event_id"].eq("").any():
        raise ValueError("Every event must have an event_id")
    if df["event_id"].duplicated().any():
        raise ValueError("event_id values must be unique")
    if df["event"].eq("").any():
        raise ValueError("Every event must have an event type")
    return df.reset_index(drop=True)


def detect(logs: pd.DataFrame, rules: list[dict] | None = None) -> pd.DataFrame:
    df = validate_logs(logs)
    selected_rules = rules if rules is not None else load_rules()
    compiled = [(r, re.compile(r["pattern"], flags=re.IGNORECASE)) for r in selected_rules]
    findings: list[dict] = []
    for row in df.to_dict(orient="records"):
        content = f"{row['event']} | {row['details']}"
        for rule, regex in compiled:
            match = regex.search(content)
            if match is None:
                continue
            tid = rule["technique_id"]
            findings.append({
                **{k: row[k] for k in ("event_id", "timestamp", "source", "host", "user", "event")},
                "rule_id": rule["id"],
                "detection": rule["name"],
                "severity": rule["severity"],
                "score": SEVERITY_SCORES[rule["severity"]],
                "mitre_id": tid,
                "technique": rule["technique"],
                "tactic": rule["tactic"],
                "mitre_url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
                "matched_indicator": match.group(0),
                "evidence": row["details"],
                "explanation": rule["explanation"],
                "recommendation": rule["recommendation"],
                "status": "Needs analyst review",
            })
    return pd.DataFrame(findings, columns=FINDING_COLUMNS)


def report_text(logs: pd.DataFrame, findings: pd.DataFrame) -> str:
    alerted = findings["event_id"].nunique() if not findings.empty else 0
    lines = [
        "SOC THREAT DETECTION & MITRE ATT&CK — RULE-BASED LAB",
        "=" * 56,
        "Dataset: uploaded or bundled CSV; sample data is synthetic",
        "Method: offline regex rules; no ML training or AI inference",
        f"Input events: {len(logs)}",
        f"Candidate alerts: {len(findings)}",
        f"Events with alerts: {alerted}",
        f"Events without alerts: {len(logs)-alerted}",
        f"Unique ATT&CK techniques: {findings['mitre_id'].nunique() if not findings.empty else 0}",
        "",
        "ALERT SEVERITY COUNTS",
    ]
    for name in SEVERITY_SCORES:
        count = int((findings["severity"] == name).sum()) if not findings.empty else 0
        lines.append(f"{name}: {count}")
    lines.extend(["", "CANDIDATE FINDINGS"])
    if findings.empty:
        lines.append("No indicators matched the current rule set.")
    else:
        for item in findings.itertuples(index=False):
            lines.append(f"{item.event_id} | {item.severity} | {item.detection} | {item.mitre_id} | {item.host}")
    lines.extend([
        "", "LIMITATIONS",
        "Matches are hypotheses to triage, not confirmed incidents.",
        "Rules can produce false positives and miss real attacks.",
        "Severity scores are demonstrative priorities, not measured probabilities.",
        "MITRE ATT&CK: https://attack.mitre.org/",
    ])
    return "\n".join(lines) + "\n"


def export_csv(df: pd.DataFrame) -> bytes:
    """Escape potentially dangerous spreadsheet formulas in downloaded CSV cells."""
    safe = df.copy().fillna("")
    for col in safe.columns:
        if pd.api.types.is_object_dtype(safe[col]):
            safe[col] = safe[col].map(
                lambda v: "'" + v if isinstance(v, str) and v.lstrip().startswith(("=", "+", "-", "@")) else v
            )
    return safe.to_csv(index=False, quoting=csv.QUOTE_MINIMAL).encode("utf-8")
