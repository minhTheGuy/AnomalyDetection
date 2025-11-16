import os
import requests
import json
import pandas as pd
import urllib3
from core.config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    RAW_JSON_PATH,
    CSV_PATH,
    get_requests_verify,
)
from utils.common import safe_save_csv, print_header
from data_processing.common import parse_hits_to_dataframe

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_logs(limit: int = 1000):
    """
    Lấy log mới nhất từ Wazuh/OpenSearch, lưu ra CSV_PATH.
    Trả về danh sách log dưới dạng dict.

    Args:
        limit: Số log tối đa cần lấy

    Returns:
        List[dict]: Danh sách log dạng dict

    """
    
    # Đảm bảo thư mục data/ tồn tại
    os.makedirs(os.path.dirname(RAW_JSON_PATH), exist_ok=True)

    query = {
        "size": 10000,
        "_source": [
            "@timestamp",
            "timestamp",
            "agent.name",
            "agent.ip",
            "rule.id",
            "rule.level",
            "rule.groups",
            "rule.description",
            "decoder.name",
            "location",

            # Syscheck fields
            "syscheck.event",
            "syscheck.path",
            "syscheck.size_after",
            "syscheck.sha256_after",
            "syscheck.uname_after",
            "syscheck.mtime_after",

            # Rootcheck / audit
            "data.file",
            "data.title",

            # Suricata alert
            "data.event_type",
            "data.app_proto",
            "data.proto",
            "data.src_ip",
            "data.src_port",
            "data.dest_ip",
            "data.dest_port",
            "data.alert.severity",
            "data.alert.signature",
            "data.alert.category",

            # Suricata flow stats
            "data.flow.bytes_toserver",
            "data.flow.bytes_toclient",
            "data.flow.pkts_toserver",
            "data.flow.pkts_toclient",

            "full_log"
        ],
        "query": {"match_all": {}}
    }


    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
    print(f"Đang truy vấn dữ liệu từ {url} ...")

    resp = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=get_requests_verify()
    )
    resp.raise_for_status()
    data = resp.json()

    # Lưu bản raw JSON để tham chiếu / debug
    with open(RAW_JSON_PATH, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Đã lưu file JSON thô → {RAW_JSON_PATH}")

    # Parse hits -> DataFrame
    hits = data.get("hits", {}).get("hits", [])
    df = parse_hits_to_dataframe(hits)

    # Ghi CSV cuối cùng
    if safe_save_csv(df, CSV_PATH):
        print(f"Đã lưu {len(df)} dòng log → {CSV_PATH}")

    return df.head(limit).to_dict(orient="records")

