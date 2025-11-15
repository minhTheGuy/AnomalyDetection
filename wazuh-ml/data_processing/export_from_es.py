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

    # Parse hits -> rows
    hits = data.get("hits", {}).get("hits", [])
    rows = []
    for h in hits:
        src = h.get("_source", {})
        rule = src.get("rule", {}) or {}
        dat = src.get("data", {}) or {}
        agent = src.get("agent", {}) or {}
        syscheck = src.get("syscheck", {}) or {}
        alert = dat.get("alert", {}) or {}
        flow = dat.get("flow", {}) or {}

        # Tính bytes và length từ flow stats nếu có
        bytes_total = None
        if flow.get("bytes_toserver") is not None or flow.get("bytes_toclient") is not None:
            bytes_total = (flow.get("bytes_toserver") or 0) + (flow.get("bytes_toclient") or 0)
        
        # Tính length từ syscheck size_after nếu có
        length = syscheck.get("size_after") or None

        rows.append({
            # Timestamp
            "timestamp": src.get("@timestamp") or src.get("timestamp"),
            
            # Agent info
            "agent": agent.get("name"),
            "agent_ip": agent.get("ip"),
            
            # Rule info
            "rule_id": rule.get("id"),
            "rule_level": rule.get("level"),
            "rule_groups": rule.get("groups"),      # có thể là list
            "event_desc": rule.get("description"),
            
            # Decoder & location
            "decoder": src.get("decoder", {}).get("name") if isinstance(src.get("decoder"), dict) else src.get("decoder"),
            "location": src.get("location"),
            
            # Syscheck (File Integrity Monitoring)
            "syscheck_event": syscheck.get("event"),
            "syscheck_path": syscheck.get("path"),
            "syscheck_size": syscheck.get("size_after"),
            "syscheck_sha256": syscheck.get("sha256_after"),
            "syscheck_uname": syscheck.get("uname_after"),
            "syscheck_mtime": syscheck.get("mtime_after"),
            
            # Rootcheck / audit
            "data_file": dat.get("file"),
            "data_title": dat.get("title"),
            
            # Network data (Suricata/IDS)
            "event_type": dat.get("event_type"),
            "app_proto": dat.get("app_proto"),
            "proto": dat.get("proto"),
            "src_ip": dat.get("src_ip") or dat.get("srcip"),  # Hỗ trợ cả 2 tên
            "src_port": dat.get("src_port") or dat.get("srcport"),  # Hỗ trợ cả 2 tên
            "dst_ip": dat.get("dest_ip") or dat.get("destip") or dat.get("dst_ip") or dat.get("dstip"),  # Hỗ trợ nhiều tên
            "dst_port": dat.get("dest_port") or dat.get("destport") or dat.get("dst_port") or dat.get("dstport"),  # Hỗ trợ nhiều tên
            
            # Suricata alert info
            "alert_severity": alert.get("severity"),
            "alert_signature": alert.get("signature"),
            "alert_category": alert.get("category"),
            
            # Flow stats (bytes và packets)
            "bytes_toserver": flow.get("bytes_toserver"),
            "bytes_toclient": flow.get("bytes_toclient"),
            "pkts_toserver": flow.get("pkts_toserver"),
            "pkts_toclient": flow.get("pkts_toclient"),
            
            # Computed fields
            "bytes": bytes_total,  # Tổng bytes từ flow
            "length": length,  # Từ syscheck hoặc None
            
            # Full log (optional, có thể rất dài)
            "full_log": src.get("full_log")
        })

    df = pd.DataFrame(rows)

    # CHẶN LỖI Ở ĐÂY:
    # Bất kỳ ô nào là list (ví dụ ["sshd","authentication_success"]) -> convert sang chuỗi "sshd,authentication_success"
    def normalize_cell(x):
        if isinstance(x, list):
            return ", ".join([str(i) for i in x])
        return x

    df = df.map(normalize_cell)

    # Bây giờ mọi ô đều hashable -> có thể drop_duplicates an toàn
    df = df.drop_duplicates()

    # Sắp xếp theo thời gian (nếu timestamp có None, pandas vẫn chịu được sort_values với na_position)
    df = df.sort_values(by="timestamp", na_position="last", ignore_index=True)

    # Ghi CSV cuối cùng
    df.to_csv(CSV_PATH, index=False)
    print(f"Đã lưu {len(df)} dòng log → {CSV_PATH}")

    return df.head(limit).to_dict(orient="records")

if __name__ == "__main__":
    fetch_logs()
