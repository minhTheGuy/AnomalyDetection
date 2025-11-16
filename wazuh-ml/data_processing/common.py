"""
Common utilities cho data processing
"""

import pandas as pd
from typing import List, Dict


def parse_hits_to_dataframe(hits: List[Dict]) -> pd.DataFrame:
    """
    Parse Elasticsearch hits thành DataFrame
    
    Args:
        hits: List of hit dictionaries từ Elasticsearch response
    
    Returns:
        DataFrame với parsed data
    """
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

    # Normalize cells: convert list to string
    def normalize_cell(x):
        if isinstance(x, list):
            return ", ".join([str(i) for i in x])
        return x

    df = df.map(normalize_cell)
    df = df.drop_duplicates()
    df = df.sort_values(by="timestamp", na_position="last", ignore_index=True)

    # Thay thế newlines bằng spaces
    if 'full_log' in df.columns:
        df['full_log'] = df['full_log'].astype(str).str.replace('\n', ' | ', regex=False)
        df['full_log'] = df['full_log'].str.replace('\r', '', regex=False)

    return df

