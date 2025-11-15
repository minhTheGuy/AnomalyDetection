import os
from dotenv import load_dotenv

# Load .env if present (no-op if missing)
load_dotenv()

# Wazuh Indexer (OpenSearch)
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200")
WAZUH_INDEX_PATTERN = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")

INDEXER_USER = os.getenv("INDEXER_USER", "")
INDEXER_PASS = os.getenv("INDEXER_PASS", "")

# Data paths
RAW_JSON_PATH = os.getenv("RAW_JSON_PATH", "data/security_logs_raw.json")
CSV_PATH = os.getenv("CSV_PATH", "data/security_logs.csv")
ANALYZED_CSV_PATH = os.getenv("ANALYZED_CSV_PATH", "data/security_logs_analyzed.csv")
MODEL_PATH = os.getenv("MODEL_PATH", "data/model_isoforest.pkl")
ANOMALIES_CSV_PATH = os.getenv("ANOMALIES_CSV_PATH", "data/anomalies.csv")

# Wazuh Manager API (for pushing alerts)
WAZUH_MANAGER_API = os.getenv("WAZUH_MANAGER_API", "https://127.0.0.1:55000")
WAZUH_MANAGER_USER = os.getenv("WAZUH_MANAGER_USER", "")
WAZUH_MANAGER_PASS = os.getenv("WAZUH_MANAGER_PASS", "")

# SSL verification
# VERIFY_SSL: "true"/"false" (case-insensitive). Default false for lab; set true in production
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes", "on")

# Optional path to a CA bundle (PEM) for self-signed certs
CA_BUNDLE_PATH = os.getenv("CA_BUNDLE_PATH", "")

# Helper for requests.verify parameter: returns bool or CA path
def get_requests_verify():
    if not VERIFY_SSL:
        return False
    return CA_BUNDLE_PATH if CA_BUNDLE_PATH else True

# Dynamic threshold configuration (for reducing false positives)
DYNAMIC_THRESHOLD_ENABLE = os.getenv("DYNAMIC_THRESHOLD_ENABLE", "true").strip().lower() in ("1", "true", "yes", "on")
TARGET_ANOMALY_RATE = float(os.getenv("TARGET_ANOMALY_RATE", "0.06"))  # default 6% to improve recall
MIN_ANOMALY_RATE = float(os.getenv("MIN_ANOMALY_RATE", "0.01"))       # 1%
MAX_ANOMALY_RATE = float(os.getenv("MAX_ANOMALY_RATE", "0.10"))       # 10%

# Training configuration
# MODEL_TYPE: 'ensemble' | 'single'
MODEL_TYPE = os.getenv("MODEL_TYPE", "ensemble").strip().lower()

# Single-model (IsolationForest) normalization
SINGLE_IF_NORMALIZE = os.getenv("SINGLE_IF_NORMALIZE", "true").strip().lower() in ("1", "true", "yes", "on")

# LLM analysis configuration
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").strip().lower()  # 'openai' | 'local'
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "random-key")
LLM_MAX_EVENTS = int(os.getenv("LLM_MAX_EVENTS", "100"))

# Classification model configuration
CLASSIFIER_MODEL_PATH = os.getenv("CLASSIFIER_MODEL_PATH", "data/classifier_model.pkl")
ENABLE_CLASSIFICATION = os.getenv("ENABLE_CLASSIFICATION", "true").strip().lower() in ("1", "true", "yes", "on")
