# SOC Threat Detection & MITRE ATT&CK Mapping

## Project Overview

A cybersecurity project that simulates Security Operations Center (SOC) threat detection using Python and the MITRE ATT&CK framework.

The system analyzes simulated SIEM security logs, identifies suspicious events using rule-based detection, maps potential threats to MITRE ATT&CK techniques, assigns severity levels, and generates interactive security dashboards.

## Technologies Used

- Python
- Google Colab
- Pandas
- MITRE ATT&CK Framework
- STIX
- Plotly
- Regular Expressions (Regex)
- SIEM Log Analysis

## Key Features

- **Security Log Analysis:** Processes simulated SIEM security events.
- **Threat Detection:** Identifies suspicious activity using predefined detection rules.
- **MITRE ATT&CK Mapping:** Maps detected events to corresponding ATT&CK technique IDs.
- **Severity Classification:** Categorizes security alerts as Critical, High, or Medium.
- **Automated Security Reporting:** Generates reports containing potential threats and mapped techniques.
- **Interactive SOC Dashboard:** Visualizes alert severity and detection frequency using Plotly.
- **Data Export:** Exports security findings and reports for further investigation.

## Project Architecture

1. Generate synthetic SIEM security logs.
2. Analyze security events using Python.
3. Apply rule-based threat detection.
4. Map candidate alerts to MITRE ATT&CK techniques.
5. Classify events by severity.
6. Generate security reports and interactive dashboards.

## Sample Dataset and Results

The project uses a controlled dataset containing:

| Metric | Result |
|---|---|
| Simulated security events | 12 |
| Rule-based detections | 10 |
| Unflagged routine events | 2 |
| MITRE ATT&CK mapping | Implemented |
| Interactive dashboard | Implemented |

These results relate to synthetic test data and do not represent real-world detection accuracy.

## Project Files

- `SOC_Threat_Detection_MITRE_ATTACK.ipynb` — Main Python notebook
- `siem_logs.csv` — Simulated security event logs
- `detection_rules.csv` — Threat detection rules
- `threat_findings.csv` — Detected events and MITRE mappings
- `security_report.txt` — Automated security report
- `soc_dashboard.html` — Interactive SOC dashboard

## How to Run

1. Download the project notebook.
2. Open it in Google Colab.
3. Select **Runtime → Run all**.
4. Execute the threat detection and MITRE mapping workflow.
5. Review the generated alerts and dashboard.
6. Download the security reports and findings.

The notebook attempts to retrieve official MITRE ATT&CK STIX data. If unavailable, it uses a limited built-in technique reference.

## Security Applications

This project demonstrates practical concepts relevant to:

- Security Operations Centers (SOC)
- Security Information and Event Management (SIEM)
- Threat Detection and Analysis
- MITRE ATT&CK Mapping
- Security Event Correlation
- Cybersecurity Reporting and Visualization

## Project Limitations

This is a rule-based cybersecurity prototype, not a trained artificial intelligence model or production SIEM platform.

All security logs are synthetic. Detection results require further investigation before being considered confirmed security incidents.

## References

- MITRE ATT&CK: https://attack.mitre.org/
- MITRE CTI Repository: https://github.com/mitre/cti

## Conclusion

The project demonstrates how security event logs can be processed, classified, mapped to known adversarial techniques, and visualized to support security monitoring and investigation workflows.
