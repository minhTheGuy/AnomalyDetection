"""
config.py - Configuration and constants for the NIDS pipeline
"""

from pathlib import Path

# Paths
PROJECT_DIR = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_DIR / 'data'
MODELS_DIR = DATA_DIR / 'models'
CAPTURE_DIR = DATA_DIR / 'captured'
PCAP_DIR = CAPTURE_DIR / 'pcap'
FLOWS_DIR = CAPTURE_DIR / 'flows'
RESULTS_DIR = DATA_DIR / 'reports'
LOGS_DIR = PROJECT_DIR / 'logs'

# Create directories
for d in [PCAP_DIR, FLOWS_DIR, RESULTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)


def get_latest_model(prefix: str, extension: str = '.pkl') -> Path:
    """Get the latest model file by prefix"""
    models = list(MODELS_DIR.glob(f'{prefix}*{extension}'))
    if not models:
        return MODELS_DIR / f'{prefix}{extension}'
    # Prefer 'latest' version if exists
    for m in models:
        if 'latest' in m.name:
            return m
    # Otherwise get most recent by modification time
    return max(models, key=lambda p: p.stat().st_mtime)


# Model paths - use actual model names
XGBOOST_MODEL_PATH = get_latest_model('cicflowmeter_model_')
IFOREST_MODEL_PATH = get_latest_model('isolation_forest_')
ARTIFACTS_PATH = MODELS_DIR / 'cicflowmeter_artifacts.pkl'


# Feature mapping: cicflowmeter output -> CIC-IDS-2017 format (for model compatibility)
# This maps the lowercase cicflowmeter column names to the original training data format
FEATURE_MAPPING_REVERSE = {
    'flow_duration': 'Flow Duration',
    'dst_port': 'Destination Port',
    'destination_port': 'Destination Port',
    'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'bwd_pkt_len_std': 'Bwd Packet Length Std',
    'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std',
    'flow_iat_max': 'Flow IAT Max',
    'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total',
    'fwd_iat_mean': 'Fwd IAT Mean',
    'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max',
    'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_mean': 'Bwd IAT Mean',
    'bwd_iat_std': 'Bwd IAT Std',
    'bwd_iat_max': 'Bwd IAT Max',
    'bwd_pkts_s': 'Bwd Packets/s',
    'pkt_len_max': 'Max Packet Length',
    'pkt_len_mean': 'Packet Length Mean',
    'pkt_len_std': 'Packet Length Std',
    'pkt_len_var': 'Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count',
    'psh_flag_cnt': 'PSH Flag Count',
    'ack_flag_cnt': 'ACK Flag Count',
    'pkt_size_avg': 'Average Packet Size',
    'bwd_seg_size_avg': 'Avg Bwd Segment Size',
    'init_fwd_win_byts': 'Init_Win_bytes_forward',
    'active_mean': 'Active Mean',
    'active_min': 'Active Min',
    'idle_mean': 'Idle Mean',
    'idle_std': 'Idle Std',
    'idle_max': 'Idle Max',
    'idle_min': 'Idle Min',
    # Additional mappings for common variations
    'tot_fwd_pkts': 'Total Fwd Packets',
    'tot_bwd_pkts': 'Total Backward Packets',
    'totlen_fwd_pkts': 'Total Length of Fwd Packets',
    'totlen_bwd_pkts': 'Total Length of Bwd Packets',
    'fwd_pkt_len_max': 'Fwd Packet Length Max',
    'fwd_pkt_len_min': 'Fwd Packet Length Min',
    'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'fwd_pkt_len_std': 'Fwd Packet Length Std',
    'bwd_pkt_len_min': 'Bwd Packet Length Min',
    'min_pkt_len': 'Min Packet Length',
    'pkt_len_min': 'Min Packet Length',
    'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s',
    'fwd_pkts_s': 'Fwd Packets/s',
    'fwd_iat_min': 'Fwd IAT Min',
    'bwd_iat_min': 'Bwd IAT Min',
    'fwd_psh_flags': 'Fwd PSH Flags',
    'fwd_header_len': 'Fwd Header Length',
    'bwd_header_len': 'Bwd Header Length',
    'down_up_ratio': 'Down/Up Ratio',
    'fwd_seg_size_avg': 'Avg Fwd Segment Size',
    'subflow_fwd_pkts': 'Subflow Fwd Packets',
    'subflow_fwd_byts': 'Subflow Fwd Bytes',
    'subflow_bwd_pkts': 'Subflow Bwd Packets',
    'subflow_bwd_byts': 'Subflow Bwd Bytes',
    'init_bwd_win_byts': 'Init_Win_bytes_backward',
    'fwd_act_data_pkts': 'act_data_pkt_fwd',
    'fwd_seg_size_min': 'min_seg_size_forward',
    'active_max': 'Active Max',
    'active_std': 'Active Std',
    'syn_flag_cnt': 'SYN Flag Count',
    'rst_flag_cnt': 'RST Flag Count',
    'urg_flag_cnt': 'URG Flag Count',
    'cwe_flag_cnt': 'CWE Flag Count',
    'ece_flag_cnt': 'ECE Flag Count',
}

# Legacy mapping (CIC-IDS-2017 -> cicflowmeter) for backwards compatibility
FEATURE_MAPPING = {v: k for k, v in FEATURE_MAPPING_REVERSE.items()}


# ============================================================================
# Whitelist - IPs to exclude from detection
# ============================================================================

def load_whitelist() -> set:
    """Load whitelisted IPs from config file and environment"""
    import os
    whitelist = set()
    
    # Load from file
    whitelist_file = PROJECT_DIR / 'config' / 'whitelist.txt'
    if whitelist_file.exists():
        with open(whitelist_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    whitelist.add(line)
    
    # Load from environment
    env_ips = os.getenv('WHITELIST_IPS', '')
    for ip in env_ips.replace('"', '').replace("'", '').split(','):
        ip = ip.strip()
        if ip:
            whitelist.add(ip)
    
    return whitelist

WHITELIST_IPS = load_whitelist()
