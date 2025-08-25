#!/usr/bin/env python3

import argparse
import json
import joblib
import pandas as pd
from pathlib import Path

FEATURES = [
    "Init_Win_bytes_forward",
    "Destination Port",
    "Packet Length Variance",
    "Average Packet Size",
    "Packet Length Std",
    "Max Packet Length",
    "Subflow Fwd Bytes",
    "Bwd Packet Length Max",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Fwd Packet Length Min",
    "Bwd Packet Length Std",
    "Bwd Packet Length Min",
    "Init_Win_bytes_backward",
    "Fwd Packet Length Std",
    "Packet Length Mean",
    "Fwd Header Length",
    "Fwd Packet Length Max",
    "Fwd Header Length.1",
    "Bwd Header Length",
]

def main(csv_path, model_path, out_path):

    df = pd.read_csv(csv_path, usecols=lambda c: c in FEATURES)

    missing = [c for c in FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f"CSV is missing expected columns: {missing}")

    X = df[FEATURES]

    model = joblib.load(model_path)
    y_pred = model.predict(X)
    df["pred_label"] = y_pred

    df["Packet"] = range(1, len(df) + 1)

    df["attack_indicator"] = df["pred_label"].map({1: "ATTACK", 0: "SAFE"})

    df = df.rename(columns={"pred_label": "Prediction"})

    df[["Packet", "Prediction"]].to_json(out_path, orient="records", lines=True)

    print(f"Saved {len(df):,} rows to {out_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv",   required=True, help="input .csv")
    ap.add_argument("--model", required=True, help="trained .joblib model")
    ap.add_argument("--output",   required=True, help="output .json")
    args = ap.parse_args()

    main(args.csv, args.model, args.output)
