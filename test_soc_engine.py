"""Run with: python -m unittest -v test_soc_engine.py"""
import unittest
from pathlib import Path

import pandas as pd

from soc_engine import detect, export_csv, load_rules, report_text, validate_logs

ROOT = Path(__file__).parent


class SOCEngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sample = pd.read_csv(ROOT / "sample_logs.csv", dtype=str).fillna("")
        cls.rules = load_rules()

    def test_sample_counts(self):
        f = detect(self.sample, self.rules)
        self.assertEqual(len(self.sample), 12)
        self.assertEqual(len(f), 10)
        self.assertEqual(f.event_id.nunique(), 10)

    def test_benign_not_flagged(self):
        f = detect(self.sample, self.rules)
        self.assertTrue(set(["EVT011", "EVT012"]).isdisjoint(set(f.event_id)))

    def test_mitre_mapping(self):
        f = detect(self.sample, self.rules)
        self.assertIn("T1003.001", set(f.mitre_id))
        self.assertTrue(f.mitre_url.str.startswith("https://attack.mitre.org/techniques/").all())

    def test_valid_severity_scores(self):
        f = detect(self.sample, self.rules)
        self.assertEqual(f.loc[f.mitre_id == "T1003.001", "score"].iloc[0], 90)

    def test_empty_table_rejected(self):
        with self.assertRaisesRegex(ValueError, "no events"):
            validate_logs(self.sample.iloc[0:0])

    def test_missing_column_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing required"):
            validate_logs(self.sample.drop(columns=["details"]))

    def test_duplicate_event_ids_rejected(self):
        duplicated = pd.concat([self.sample.iloc[[0]], self.sample.iloc[[0]]], ignore_index=True)
        with self.assertRaisesRegex(ValueError, "unique"):
            validate_logs(duplicated)

    def test_case_insensitive_columns_and_event_text(self):
        one = self.sample.iloc[[0]].copy()
        one.columns = [c.upper() for c in one.columns]
        one["DETAILS"] = "POWERSHELL -ENC example"
        result = detect(one, self.rules)
        self.assertEqual(result.mitre_id.iloc[0], "T1059.001")

    def test_unknown_text_is_not_flagged(self):
        one = self.sample.iloc[[11]].copy()
        one.loc[:, "event"] = "Nothing unusual"
        one.loc[:, "details"] = "Scheduled system maintenance completed"
        self.assertEqual(len(detect(one, self.rules)), 0)

    def test_multiple_rules_same_event(self):
        one = self.sample.iloc[[0]].copy()
        one.loc[:, "details"] = "powershell -enc and unknown scheduled task created"
        results = detect(one, self.rules)
        self.assertEqual(len(results), 2)
        self.assertEqual(results.event_id.nunique(), 1)

    def test_report_contains_counts_and_limitations(self):
        findings = detect(self.sample, self.rules)
        report = report_text(self.sample, findings)
        self.assertIn("Candidate alerts: 10", report)
        self.assertIn("false positives", report)

    def test_spreadsheet_formula_escape(self):
        data = pd.DataFrame({"host": ["=HYPERLINK(\"x\")", "normal"]})
        output = export_csv(data).decode("utf-8")
        self.assertIn("'=HYPERLINK", output)
        self.assertIn("normal", output)


if __name__ == "__main__":
    unittest.main()
