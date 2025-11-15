import os
import sys
import pandas as pd
import numpy as np

# Ensure modules under wazuh-ml/ are importable when running pytest from repo root
CURRENT_DIR = os.path.dirname(__file__)
PROJECT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from detection.anomaly_tuning import AnomalyFilter, compute_dynamic_threshold, apply_threshold_to_labels


def test_anomalyfilter_whitelist_internal_ssh_business_hours():
    # Simulate a benign internal SSH success during business hours
    df = pd.DataFrame([
        {
            'event_desc': 'sshd: authentication success',
            'src_ip': '172.16.158.1',
            'is_business_hours': 1,
            'anomaly_label': -1,  # initially flagged as anomaly
            'anomaly_score': -0.5
        }
    ])

    engine = AnomalyFilter()
    out = engine.filter_anomalies(df, remove_whitelisted=True, apply_boost=False)

    # Should be marked whitelisted and filtered out from anomalies
    assert bool(out.loc[0, 'is_whitelisted']) is True
    assert out.loc[0, 'anomaly_label_filtered'] == 1


def test_dynamic_threshold_labels_target_rate():
    # Create synthetic scores (lower = more anomalous)
    rng = np.random.default_rng(42)
    scores = rng.normal(loc=0.0, scale=1.0, size=1000)

    df = pd.DataFrame({'anomaly_score': scores})
    # initial labels all normal
    df['anomaly_label'] = 1

    target = 0.03
    thr = compute_dynamic_threshold(scores, target_anomaly_rate=target, min_rate=0.01, max_rate=0.1)
    assert thr is not None

    df2 = apply_threshold_to_labels(df, thr, label_col='anomaly_label', score_col='anomaly_score')
    rate = (df2['anomaly_label'] == -1).mean()

    # Allow small tolerance around target rate
    assert abs(rate - target) < 0.01


