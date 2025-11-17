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
# MODEL_TYPE: 'ensemble' | 'single' | 'autoencoder'
MODEL_TYPE = os.getenv("MODEL_TYPE", "ensemble").strip().lower()

# Single-model (IsolationForest) normalization
SINGLE_IF_NORMALIZE = os.getenv("SINGLE_IF_NORMALIZE", "true").strip().lower() in ("1", "true", "yes", "on")

# LLM analysis configuration
# Supported providers: openai | deepseek | local
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").strip().lower()
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
LLM_MAX_EVENTS = int(os.getenv("LLM_MAX_EVENTS", "100"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "800"))

# DeepSeek-specific settings
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY", "")
DEEPSEEK_API_BASE = os.getenv("DEEPSEEK_API_BASE", "https://api.deepseek.com/v1")

# Classification model configuration
CLASSIFIER_MODEL_PATH = os.getenv("CLASSIFIER_MODEL_PATH", "data/classifier_model.pkl")
ENABLE_CLASSIFICATION = os.getenv("ENABLE_CLASSIFICATION", "true").strip().lower() in ("1", "true", "yes", "on")

# Action/Response configuration
ENABLE_ACTIONS = os.getenv("ENABLE_ACTIONS", "true").strip().lower() in ("1", "true", "yes", "on")
AUTO_EXECUTE_ACTIONS = os.getenv("AUTO_EXECUTE_ACTIONS", "true").strip().lower() in ("1", "true", "yes", "on")
ENABLE_AUTO_BLOCK = os.getenv("ENABLE_AUTO_BLOCK", "true").strip().lower() in ("1", "true", "yes", "on")
ENABLE_TELEGRAM = os.getenv("ENABLE_TELEGRAM", "false").strip().lower() in ("1", "true", "yes", "on")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
MIN_SEVERITY_FOR_BLOCK = int(os.getenv("MIN_SEVERITY_FOR_BLOCK", "3"))  # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
MIN_SEVERITY_FOR_NOTIFY = int(os.getenv("MIN_SEVERITY_FOR_NOTIFY", "2"))  # 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
ACTIONS_CSV_PATH = os.getenv("ACTIONS_CSV_PATH", "data/actions.csv")
ACTION_RESULTS_CSV_PATH = os.getenv("ACTION_RESULTS_CSV_PATH", "data/action_results.csv")

# pfSense integration configuration
ENABLE_PFSENSE = os.getenv("ENABLE_PFSENSE", "false").strip().lower() in ("1", "true", "yes", "on")
PFSENSE_METHOD = os.getenv("PFSENSE_METHOD", "ssh").strip().lower()  # 'api' or 'ssh'
PFSENSE_HOST = os.getenv("PFSENSE_HOST", "https://172.16.158.100")
PFSENSE_USERNAME = os.getenv("PFSENSE_USERNAME", "admin")
PFSENSE_PASSWORD = os.getenv("PFSENSE_PASSWORD", "pfsense")
PFSENSE_VERIFY_SSL = os.getenv("PFSENSE_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes", "on")
PFSENSE_SSH_HOST = os.getenv("PFSENSE_SSH_HOST", "172.16.158.100")
PFSENSE_SSH_USER = os.getenv("PFSENSE_SSH_USER", "admin")
PFSENSE_SSH_PASS = os.getenv("PFSENSE_SSH_PASS", "pfsense")
