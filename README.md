
## User Input — Security Logs CSV

Users can upload a CSV file containing security events.

### Required CSV Columns
- event_id
- timestamp
- source
- host
- user
- event
- details

### Example Input

```csv
event_id,timestamp,source,host,user,event,details
EVT001,2026-10-30 10:00:00,Endpoint,ws-01,alice,PowerShell Execution,Suspicious PowerShell -enc command
```

### Input Guide

![Example of required user input](input-guide.png)

### Try the Application

Download `sample_logs.csv` from this repository
and upload it using the "Upload your SIEM CSV" option.

The dashboard will analyze the logs, identify
suspicious events, and display MITRE ATT&CK mappings.
