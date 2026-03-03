# 02 — ML-Based Log Anomaly Detection

## Overview

This project uses **Isolation Forest** (an unsupervised machine learning algorithm) to automatically detect anomalous entries in Windows Event Log / authentication log data. The script loads a CSV of log events, trains the model, scores each entry, and outputs a flagged report — no labelled training data required.

This technique is widely used in modern SIEMs and UBA (User and Entity Behaviour Analytics) platforms such as Splunk UBA and Microsoft Sentinel.

---

## Requirements

```bash
pip install scikit-learn pandas numpy
```

---

## How to Run

```bash
# Run with default settings (reads sample_logs.csv, writes anomaly_report.csv)
python anomaly_detection.py

# Custom input/output paths
python anomaly_detection.py --input my_logs.csv --output my_report.csv

# Tune contamination rate (expected % of anomalies in your data)
python anomaly_detection.py --contamination 0.08

# Adjust the score threshold for flagging
python anomaly_detection.py --threshold -0.05
```

---

## How Isolation Forest Works

Isolation Forest detects anomalies by **isolating observations** rather than profiling normal behaviour:

1. **Random partitioning**: The algorithm randomly selects a feature and a split value to recursively partition the data into binary trees.
2. **Path length**: Anomalies, being rare and different from the majority, tend to be isolated in **fewer splits** (shorter path length).
3. **Anomaly score**: The average path length across all trees is converted to a score. Scores closer to **-1** indicate anomalies; scores near **+1** indicate normal entries.

> **Key insight**: You do not need labelled attack data — the model learns what "normal" looks like and flags statistical outliers.

---

## Feature Engineering

The following raw log fields are used as model features:

| Feature | Source Column | Why It Matters |
|---|---|---|
| `hour_of_day` | `timestamp` | Detects off-hours logins (e.g. 2 AM admin activity) |
| `user_encoded` | `user` | Unusual user accounts (service accounts logging interactively) |
| `event_id` | `event_id` | Rare event types signal suspicious activity |
| `source_ip_encoded` | `source_ip` | External IPs or unusual internal subnets |
| `action_encoded` | `action` | Unusual actions (account creation, privilege escalation) |
| `status_encoded` | `status` | Failure spikes indicate brute force / misconfiguration |

Categorical columns (`user`, `source_ip`, `action`, `status`) are label-encoded to integers before training.

---

## Interpreting Anomaly Scores

| Score Range | Interpretation |
|---|---|
| `< -0.1` | **High anomaly** — prioritise for investigation |
| `-0.1` to `0.0` | **Moderate anomaly** — worth reviewing |
| `> 0.0` | **Normal** — consistent with baseline behaviour |

The `anomaly_report.csv` output includes:
- All original columns from the input CSV
- `anomaly_score` — the Isolation Forest decision function score
- `is_anomaly` — raw model prediction (`-1` = anomaly, `1` = normal)
- `flagged` — `1` if the entry falls below the score threshold, `0` otherwise

---

## Sample Output

```
[*] Loading log data from: sample_logs.csv
[*] Loaded 100 log entries.
[*] Engineering features...
[*] Training Isolation Forest (contamination=0.1, n_estimators=100)...

[+] Detection complete.
    Total log entries  : 100
    Flagged as anomaly : 10 (10.0%)
    Anomaly score range: [-0.1823, 0.0912]

[+] Top anomalous entries:
timestamp                user          event_id  source_ip       action        status  anomaly_score
2025-10-14T08:23:11Z     administrator  4625     185.220.101.45  failed_logon  failure  -0.1823
2025-10-14T02:14:07Z     admin          4720     10.0.0.21       account_created success -0.1641
...

[+] Full anomaly report saved to: anomaly_report.csv
```

---

## Limitations and False Positive Considerations

| Limitation | Mitigation |
|---|---|
| **Label-encoding treats all categories as equally spaced** | Use one-hot encoding for higher accuracy on large datasets |
| **No temporal context** — each row is treated independently | Add rolling window features (e.g. failed_logins_last_5min) |
| **Sensitive to contamination parameter** | Tune with domain knowledge; start at 5–10% |
| **New legitimate users/IPs flagged as anomalous** | Maintain an allowlist; retrain model periodically |
| **Doesn't detect slow, low-volume attacks** | Combine with rule-based detection for threshold alerts |

> **Always review flagged entries with analyst context before acting.** ML anomaly scores are a prioritisation signal, not a verdict.

---

## MITRE ATT&CK Relevance

Anomaly detection on auth logs can surface activity related to:

| Technique | ID | Indicator in Logs |
|---|---|---|
| Brute Force | **T1110** | High failure count from single source IP |
| Valid Accounts | **T1078** | Unusual logon times / locations for known accounts |
| Account Manipulation | **T1098** | Unexpected account creation (`event_id=4720`) |
| Privilege Escalation | **T1068** | Special privileges assigned (`event_id=4672`) at odd hours |
| Lateral Movement | **T1021** | Internal IP logging into multiple hosts sequentially |

---

## Files

| File | Description |
|---|---|
| `anomaly_detection.py` | Main Python detection script |
| `sample_logs.csv` | 100 rows of synthetic Windows/auth log data |
| `anomaly_report.csv` | Generated output (created when you run the script) |
| `README.md` | This file |
