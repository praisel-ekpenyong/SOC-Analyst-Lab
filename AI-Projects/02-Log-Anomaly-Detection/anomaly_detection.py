#!/usr/bin/env python3
"""
ML-Based Log Anomaly Detection
================================
Loads a Windows Event Log / auth log CSV, applies Isolation Forest to detect
anomalous entries, and outputs a flagged report CSV with anomaly scores.

Dependencies:
    pip install scikit-learn pandas numpy

Usage:
    python anomaly_detection.py
    python anomaly_detection.py --input sample_logs.csv --output anomaly_report.csv
    python anomaly_detection.py --contamination 0.08 --threshold -0.05
"""

import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# Feature engineering
# ---------------------------------------------------------------------------

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Convert raw log fields into numeric features suitable for Isolation Forest.

    Features used:
      - hour_of_day   : hour extracted from timestamp (detects off-hours activity)
      - user_encoded  : label-encoded user name
      - event_id      : Windows Event ID (numeric, already meaningful)
      - source_ip_enc : label-encoded source IP address
      - action_encoded: label-encoded action string
      - status_encoded: label-encoded status (success=0 / failure=1 after encoding)
    """
    df = df.copy()

    # Parse timestamps and extract hour of day
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["hour_of_day"] = df["timestamp"].dt.hour

    # Label-encode categorical columns
    le = LabelEncoder()
    for col in ["user", "source_ip", "action", "status"]:
        df[f"{col}_encoded"] = le.fit_transform(df[col].astype(str))

    return df


def build_feature_matrix(df: pd.DataFrame) -> np.ndarray:
    """Select and return the numeric feature columns as a numpy array."""
    feature_cols = [
        "hour_of_day",
        "user_encoded",
        "event_id",
        "source_ip_encoded",
        "action_encoded",
        "status_encoded",
    ]
    return df[feature_cols].values


# ---------------------------------------------------------------------------
# Main detection pipeline
# ---------------------------------------------------------------------------

def run_detection(
    input_path: str,
    output_path: str,
    contamination: float,
    threshold: float,
    n_estimators: int,
    random_state: int,
) -> None:
    """Load logs, run Isolation Forest, and write the anomaly report."""

    # --- Load data ---
    print(f"[*] Loading log data from: {input_path}")
    try:
        df = pd.read_csv(input_path)
    except FileNotFoundError:
        print(f"ERROR: Input file not found: {input_path}")
        sys.exit(1)
    except Exception as exc:
        print(f"ERROR reading CSV: {exc}")
        sys.exit(1)

    required_cols = {"timestamp", "user", "event_id", "source_ip", "action", "status"}
    missing = required_cols - set(df.columns)
    if missing:
        print(f"ERROR: Missing required columns: {missing}")
        sys.exit(1)

    print(f"[*] Loaded {len(df)} log entries.")

    # --- Feature engineering ---
    print("[*] Engineering features...")
    df_feat = engineer_features(df)
    X = build_feature_matrix(df_feat)

    # --- Train Isolation Forest ---
    print(f"[*] Training Isolation Forest (contamination={contamination}, n_estimators={n_estimators})...")
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
    )
    model.fit(X)

    # --- Score and predict ---
    # decision_function returns anomaly scores: more negative = more anomalous
    df["anomaly_score"] = model.decision_function(X)
    # predict returns -1 for anomalies, 1 for normal entries
    df["is_anomaly"] = model.predict(X)

    # Apply the score threshold (entries below threshold are flagged)
    df["flagged"] = (df["anomaly_score"] < threshold).astype(int)

    # --- Report ---
    anomalies = df[df["flagged"] == 1].sort_values("anomaly_score")
    total = len(df)
    flagged_count = len(anomalies)

    print(f"\n[+] Detection complete.")
    print(f"    Total log entries  : {total}")
    print(f"    Flagged as anomaly : {flagged_count} ({flagged_count/total*100:.1f}%)")
    print(f"    Anomaly score range: [{df['anomaly_score'].min():.4f}, {df['anomaly_score'].max():.4f}]")

    if flagged_count > 0:
        print(f"\n[+] Top anomalous entries:")
        display_cols = ["timestamp", "user", "event_id", "source_ip", "action", "status", "anomaly_score"]
        print(anomalies[display_cols].head(10).to_string(index=False))

    # --- Save report ---
    report = df.sort_values("anomaly_score")
    report.to_csv(output_path, index=False)
    print(f"\n[+] Full anomaly report saved to: {output_path}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="ML-Based Log Anomaly Detection using Isolation Forest"
    )
    parser.add_argument(
        "--input",
        default="sample_logs.csv",
        help="Path to input log CSV (default: sample_logs.csv)",
    )
    parser.add_argument(
        "--output",
        default="anomaly_report.csv",
        help="Path for output anomaly report CSV (default: anomaly_report.csv)",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.1,
        help="Expected proportion of anomalies in the dataset (default: 0.1)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.0,
        help="Anomaly score threshold; entries below this are flagged (default: 0.0)",
    )
    parser.add_argument(
        "--n-estimators",
        type=int,
        default=100,
        help="Number of trees in the Isolation Forest (default: 100)",
    )
    parser.add_argument(
        "--random-state",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)",
    )
    args = parser.parse_args()

    run_detection(
        input_path=args.input,
        output_path=args.output,
        contamination=args.contamination,
        threshold=args.threshold,
        n_estimators=args.n_estimators,
        random_state=args.random_state,
    )


if __name__ == "__main__":
    main()
