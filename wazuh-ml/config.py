# config.py
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
