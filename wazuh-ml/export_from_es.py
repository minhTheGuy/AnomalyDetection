import os
import requests
import json
import pandas as pd
import urllib3
from config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    RAW_JSON_PATH,
    CSV_PATH,
    VERIFY_SSL,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def fetch_logs():
    # Đảm bảo thư mục data/ tồn tại
    os.makedirs(os.path.dirname(RAW_JSON_PATH), exist_ok=True)

    # Query đã mở rộng trường
    query = {
        "size": 10000,
        "_source": [
            "@timestamp",
            "agent.name",
            "integration",
            "rule.id",
            "rule.level",
            "rule.groups",
            "rule.category",
            "rule.description",
            "data.proto",
            "data.srcip",
            "data.srcport",
            "data.dstip",
            "data.dstport",
            "data.bytes",
            "data.len"
        ],
        "query": { "match_all": {} }
    }

    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
    print(f"📡 Đang truy vấn dữ liệu từ {url} ...")

    resp = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=VERIFY_SSL
    )
    resp.raise_for_status()
    data = resp.json()

    # Lưu bản raw JSON để tham chiếu / debug
    with open(RAW_JSON_PATH, "w") as f:
        json.dump(data, f, indent=2)
    print(f"✅ Đã lưu file JSON thô → {RAW_JSON_PATH}")

    # Parse hits -> rows
    hits = data.get("hits", {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source", {})
        rule = src.get("rule", {}) or {}
        dat = src.get("data", {}) or {}
        agent = src.get("agent", {}) or {}

        rows.append({
            "timestamp": src.get("@timestamp"),
            "agent": agent.get("name"),
            "integration": src.get("integration"),
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_groups": rule.get("groups"),      # có thể là list
            "rule_category": rule.get("category"),
            "event_desc": rule.get("description"),
            "proto": dat.get("proto"),
            "src_ip": dat.get("srcip"),
            "src_port": dat.get("srcport"),
            "dst_ip": dat.get("dstip"),
            "dst_port": dat.get("dstport"),
            "bytes": dat.get("bytes"),
            "length": dat.get("len")
        })

    df = pd.DataFrame(rows)

    # 🔁 CHẶN LỖI Ở ĐÂY:
    # Bất kỳ ô nào là list (ví dụ ["sshd","authentication_success"]) -> convert sang chuỗi "sshd,authentication_success"
    def normalize_cell(x):
        if isinstance(x, list):
            return ", ".join([str(i) for i in x])
        return x

    df = df.applymap(normalize_cell)

    # Bây giờ mọi ô đều hashable -> có thể drop_duplicates an toàn
    df = df.drop_duplicates()

    # Sắp xếp theo thời gian (nếu timestamp có None, pandas vẫn chịu được sort_values với na_position)
    df = df.sort_values(by="timestamp", na_position="last", ignore_index=True)

    # Ghi CSV cuối cùng
    df.to_csv(CSV_PATH, index=False)
    print(f"✅ Đã lưu {len(df)} dòng log → {CSV_PATH}")

if __name__ == "__main__":
    fetch_logs()
