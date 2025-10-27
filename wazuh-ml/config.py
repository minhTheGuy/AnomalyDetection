# config.py

WAZUH_INDEXER_URL = "https://172.16.158.150:9200"
WAZUH_INDEX_PATTERN = "wazuh-alerts-*"

INDEXER_USER = "mlreader1234"
INDEXER_PASS = "MLreader123@" 

# nơi lưu dữ liệu tạm
RAW_JSON_PATH = "data/security_logs_raw.json"
CSV_PATH = "data/security_logs.csv"
ANALYZED_CSV_PATH = "data/security_logs_analyzed.csv"
MODEL_PATH = "data/model_isoforest.pkl"

# API Wazuh Manager để đẩy alert ML
WAZUH_MANAGER_API = "https://172.16.158.150:55000"
WAZUH_MANAGER_USER = "wazuh"
WAZUH_MANAGER_PASS = "wazuh"
VERIFY_SSL = False  # lab nội bộ, cert self-signed nên tắt verify
