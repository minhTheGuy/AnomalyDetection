"""
Module tinh chỉnh anomaly detection để giảm false positives
"""
import re
from numbers import Number

import numpy as np
import pandas as pd

from utils.common import print_header, safe_load_csv
from detection.anomaly_patterns import WHITELISTED_PATTERNS, SUSPICIOUS_PATTERNS


class AnomalyFilter:
    """Filter và điều chỉnh anomaly scores để giảm false positives"""
    
    def __init__(self):
        # Whitelist: Các sự kiện được coi là bình thường
        self.whitelisted_patterns = WHITELISTED_PATTERNS
        self.suspicious_patterns = SUSPICIOUS_PATTERNS
    
    def _build_mask(self, df, conditions):
        mask = pd.Series(True, index=df.index)
        for col, values in conditions.items():
            series = df.get(col)
            if series is None:
                mask &= False
                continue
            sample = values[0]
            if isinstance(sample, str):
                pattern = "|".join(re.escape(str(v).lower()) for v in values)
                cond = series.astype(str).str.lower().str.contains(pattern, na=False, regex=True)
            else:
                if len(values) == 1 and isinstance(sample, Number):
                    cond = pd.to_numeric(series, errors="coerce") >= float(sample)
                else:
                    cond = series.isin(values)
            mask &= cond.fillna(False)
            if not mask.any():
                break
        return mask

    def _apply_patterns(self, df, patterns, result_col, reason_col, default_value):
        df = df.copy()
        df[result_col] = default_value
        df[reason_col] = ""

        for pattern_config in patterns.values():
            mask = self._build_mask(df, pattern_config["conditions"])
            if not mask.any():
                continue
            if result_col == "is_whitelisted":
                df.loc[mask, result_col] = True
                df.loc[mask, reason_col] = pattern_config["description"]
            else:
                multiplier = pattern_config.get("score_multiplier", 1.0)
                update_mask = mask & (df[result_col] < multiplier)
                df.loc[update_mask, result_col] = multiplier
                df.loc[update_mask, reason_col] = pattern_config["description"]
        return df
    
    def apply_whitelist(self, df):
        """Áp dụng whitelist để loại bỏ false positives"""
        return self._apply_patterns(df, self.whitelisted_patterns, 'is_whitelisted', 'whitelist_reason', False)
    
    def apply_suspicious_boost(self, df):
        """Tăng anomaly score cho các pattern đáng ngờ"""
        df = self._apply_patterns(df, self.suspicious_patterns, 'score_multiplier', 'suspicious_reason', 1.0)
        df['anomaly_score_original'] = df['anomaly_score']
        df['anomaly_score'] = df['anomaly_score'] * df['score_multiplier']
        return df
    
    def filter_anomalies(self, df, remove_whitelisted=True, apply_boost=True):
        """Áp dụng toàn bộ filters"""
        df = df.copy()
        df = self.apply_whitelist(df)
        
        if apply_boost:
            df = self.apply_suspicious_boost(df)
        
        # Filter anomalies
        if remove_whitelisted:
            df['anomaly_label_filtered'] = df.apply(
                lambda row: -1 if (row['anomaly_label'] == -1 and not row['is_whitelisted']) else 1,
                axis=1
            )
        else:
            df['anomaly_label_filtered'] = df['anomaly_label']
        
        return df


def compute_dynamic_threshold(scores, target_anomaly_rate=0.03, min_rate=0.01, max_rate=0.10):
    """Tính dynamic threshold dựa theo percentile với guardrails"""
    n = len(scores)
    if n == 0:
        return None
    target = max(min_rate, min(max_rate, target_anomaly_rate))
    return float(np.percentile(scores, target * 100.0))


def apply_threshold_to_labels(df, threshold, label_col='anomaly_label', score_col='anomaly_score'):
    """Áp dụng threshold động để (re)label anomalies"""
    if threshold is None or score_col not in df.columns:
        return df
    df = df.copy()
    df[label_col] = df[score_col].apply(lambda s: -1 if s <= threshold else 1)
    return df


def analyze_anomaly_distribution(df):
    """Phân tích phân bố của anomalies"""
    print_header("ANOMALY DISTRIBUTION ANALYSIS", width=70)
    
    anomalies = df[df['anomaly_label'] == -1]
    
    if len(anomalies) == 0:
        print("No anomalies detected!")
        return
    
    # By severity
    if 'severity_category' in df.columns:
        print("\nBy Severity:")
        for severity, count in anomalies['severity_category'].value_counts().items():
            print(f"  {severity:10s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By time of day
    if 'hour' in df.columns:
        print("\nBy Time:")
        for hour, count in anomalies['hour'].value_counts().sort_index().items():
            bar = "█" * int(count / len(anomalies) * 50)
            print(f"  {int(hour):02d}:00 - {count:3d} {bar}")
    
    # By agent
    if 'agent' in df.columns:
        print("\nBy Agent:")
        for agent, count in anomalies['agent'].value_counts().head(5).items():
            print(f"  {agent:20s}: {count:3d} ({count/len(anomalies)*100:.1f}%)")
    
    # By event type
    if 'event_desc' in df.columns:
        print("\nTop Event Types:")
        for event, count in anomalies['event_desc'].value_counts().head(10).items():
            print(f"  {event[:60]:60s}: {count:3d}")
    
    # Score distribution
    if 'anomaly_score' in df.columns:
        print("\nScore Distribution:")
        scores = anomalies['anomaly_score']
        print(f"  Min:    {scores.min():.4f}")
        print(f"  Q1:     {scores.quantile(0.25):.4f}")
        print(f"  Median: {scores.median():.4f}")
        print(f"  Q3:     {scores.quantile(0.75):.4f}")
        print(f"  Max:    {scores.max():.4f}")


def recommend_threshold(df, target_anomaly_rate=0.02):
    """Đề xuất threshold dựa trên phân bố scores"""
    scores = df['anomaly_score'].values
    scores_sorted = np.sort(scores)
    
    threshold_idx = int(len(scores) * target_anomaly_rate)
    recommended_threshold = scores_sorted[threshold_idx]
    
    print_header("THRESHOLD RECOMMENDATION")
    print(f"Target anomaly rate: {target_anomaly_rate*100:.1f}%")
    print(f"Recommended threshold: {recommended_threshold:.4f}")
    print(f"Expected anomalies: {threshold_idx}")
    
    print("\nThreshold Impact:")
    for percentile in [0.01, 0.02, 0.03, 0.05, 0.07, 0.10]:
        threshold = scores_sorted[int(len(scores) * percentile)]
        n_anomalies = (scores <= threshold).sum()
        print(f"  {percentile*100:4.1f}% → threshold={threshold:7.4f} → {n_anomalies:3d} anomalies")
    
    return recommended_threshold


