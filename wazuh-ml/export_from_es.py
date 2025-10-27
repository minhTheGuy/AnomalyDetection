# export_from_es.py
import requests
import json
import pandas as pd
from config import (
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    RAW_JSON_PATH,
    CSV_PATH,
    VERIFY_SSL,
)

def fetch_logs():
    query = {
        "size": 10000,
        "_source": [
            "@timestamp",
            "agent.name",
            "rule.description",
            "data.srcip",
            "data.srcport",
            "data.dstip",
            "data.dstport",
            "integration"
        ],
        "query": { "match_all": {} }
    }

    url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
    resp = requests.post(
        url,
        auth=(INDEXER_USER, INDEXER_PASS),
        json=query,
        verify=VERIFY_SSL
    )
    resp.raise_for_status()

    data = resp.json()
    with open(RAW_JSON_PATH, "w") as f:
        json.dump(data, f, indent=2)

    # chuyển sang bảng
    hits = data.get("hits", {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source", {})
        rows.append({
            "timestamp": src.get("@timestamp"),
            "agent": (src.get("agent") or {}).get("name"),
            "event_desc": (src.get("rule") or {}).get("description"),
            "src_ip": (src.get("data") or {}).get("srcip"),
            "src_port": (src.get("data") or {}).get("srcport"),
            "dst_ip": (src.get("data") or {}).get("dstip"),
            "dst_port": (src.get("data") or {}).get("dstport"),
        })

    df = pd.DataFrame(rows)
    df.to_csv(CSV_PATH, index=False)
    print(f"✅ Fetched {len(df)} rows → {CSV_PATH}")

if __name__ == "__main__":
    fetch_logs()
