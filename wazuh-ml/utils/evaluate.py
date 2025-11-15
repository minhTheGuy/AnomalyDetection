#!/usr/bin/env python3

import argparse
import os
from typing import Optional

import pandas as pd
import numpy as np
from core.config import ANALYZED_CSV_PATH


def load_analyzed(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    if 'timestamp' in df.columns:
        # Parse as timezone-aware if possible (many logs are in UTC with 'Z')
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    return df


def load_labels(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    # expected columns: run_id,type,start_ts,end_ts,src_ip,notes
    df['start_ts'] = pd.to_datetime(df['start_ts'], errors='coerce', utc=True)
    df['end_ts'] = pd.to_datetime(df['end_ts'], errors='coerce', utc=True)
    return df


def apply_time_labels(analyzed: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    if analyzed.empty or labels.empty or 'timestamp' not in analyzed.columns:
        analyzed['label'] = np.nan
        return analyzed

    analyzed = analyzed.copy()
    analyzed['label'] = 'unlabeled'

    # For efficiency, sort by time
    analyzed = analyzed.sort_values('timestamp')
    labels = labels.sort_values('start_ts')

    # Assign labels by time window. If an event falls into multiple windows, take the last one.
    for _, row in labels.iterrows():
        st, en, t = row['start_ts'], row['end_ts'], str(row['type'])
        if pd.isna(st) or pd.isna(en):
            continue
        mask = (analyzed['timestamp'] >= st) & (analyzed['timestamp'] <= en)
        analyzed.loc[mask, 'label'] = t

    return analyzed


def to_binary_labels(df: pd.DataFrame, label_col: str = 'label') -> pd.Series:
    # Positive if label starts with 'attack'
    def is_pos(x: Optional[str]) -> int:
        s = str(x).lower() if isinstance(x, str) else ''
        return 1 if s.startswith('attack') else 0
    return df[label_col].apply(is_pos)


def classification_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return {
        'tp': tp, 'fp': fp, 'fn': fn,
        'precision': precision, 'recall': recall, 'f1': f1
    }


def precision_at_k(df: pd.DataFrame, k: int) -> float:
    if k <= 0:
        return 0.0
    # Lower anomaly_score = more anomalous
    if 'anomaly_score' not in df.columns:
        return 0.0
    ranked = df.sort_values('anomaly_score', ascending=True).head(k)
    if 'label_bin' not in ranked.columns:
        return 0.0
    return float(ranked['label_bin'].mean())


def print_stats(df: pd.DataFrame):
    total = len(df)
    anomalies_raw = int((df.get('anomaly_label', pd.Series([1]*total)) == -1).sum())
    anomalies_filtered = int((df.get('anomaly_label_filtered', pd.Series([1]*total)) == -1).sum())
    print(f"Total records:           {total}")
    print(f"Anomalies (raw):         {anomalies_raw} ({anomalies_raw/total*100:.2f}%)")
    if anomalies_filtered != anomalies_raw:
        print(f"Anomalies (filtered):    {anomalies_filtered} ({anomalies_filtered/total*100:.2f}%)")

    if 'anomaly_votes' in df.columns:
        votes = df['anomaly_votes'].fillna(0)
        print("Agreement (ensemble):")
        print(f"  3/3: {int((votes==3).sum())} | 2/3: {int((votes==2).sum())} | 1/3: {int((votes==1).sum())}")


def main():
    parser = argparse.ArgumentParser(description='Evaluate anomaly detection using labels.csv time windows')
    parser.add_argument('--analyzed', type=str, default=ANALYZED_CSV_PATH, help='Path to security_logs_analyzed.csv')
    parser.add_argument('--labels', type=str, default='data/labels/labels.csv', help='Path to labels.csv')
    parser.add_argument('--since', type=str, default=None, help='ISO start time filter for analyzed')
    parser.add_argument('--until', type=str, default=None, help='ISO end time filter for analyzed')
    parser.add_argument('--k', type=int, default=50, help='K for Precision@K')
    args = parser.parse_args()

    analyzed = load_analyzed(args.analyzed)
    if args.since and 'timestamp' in analyzed.columns:
        since_ts = pd.to_datetime(args.since, errors='coerce', utc=True)
        analyzed = analyzed[analyzed['timestamp'] >= since_ts]
    if args.until and 'timestamp' in analyzed.columns:
        until_ts = pd.to_datetime(args.until, errors='coerce', utc=True)
        analyzed = analyzed[analyzed['timestamp'] <= until_ts]

    if not os.path.exists(args.labels):
        print("No labels.csv found; only printing anomaly stats.")
        print_stats(analyzed)
        return

    labels = load_labels(args.labels)
    merged = apply_time_labels(analyzed, labels)
    merged['label_bin'] = to_binary_labels(merged, 'label')

    # Use model outputs: -1 anomaly → predicted positive else negative
    if 'anomaly_label_filtered' in merged.columns:
        y_pred = (merged['anomaly_label_filtered'] == -1).astype(int).values
    else:
        y_pred = (merged['anomaly_label'] == -1).astype(int).values if 'anomaly_label' in merged.columns else np.zeros(len(merged), dtype=int)

    y_true_mask = merged['label'] != 'unlabeled'
    labeled = merged[y_true_mask].copy()

    print("\n================ EVALUATION ================")
    print_stats(merged)

    if labeled.empty:
        print("No labeled rows in the selected time range.")
        return

    y_true = labeled['label_bin'].values
    y_pred_labeled = y_pred[y_true_mask.values]
    metrics = classification_metrics(y_true, y_pred_labeled)

    print("\nLabeled subset:")
    print(f"  Labeled rows:          {len(labeled)}")
    print(f"  TP: {metrics['tp']}  FP: {metrics['fp']}  FN: {metrics['fn']}")
    print(f"  Precision:             {metrics['precision']:.3f}")
    print(f"  Recall:                {metrics['recall']:.3f}")
    print(f"  F1-score:              {metrics['f1']:.3f}")

    p_at_k = precision_at_k(labeled, args.k)
    print(f"\nPrecision@{args.k}:       {p_at_k:.3f}")


if __name__ == '__main__':
    main()


