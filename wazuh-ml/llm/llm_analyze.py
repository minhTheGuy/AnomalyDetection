import os
import json
from datetime import datetime
import pandas as pd
import requests
import urllib3
from core.config import (
    CSV_PATH,
    ANOMALIES_CSV_PATH,
    WAZUH_INDEXER_URL,
    WAZUH_INDEX_PATTERN,
    INDEXER_USER,
    INDEXER_PASS,
    get_requests_verify,
    LLM_MAX_EVENTS,
)
from llm.provider import call_llm as call_llm_provider

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def read_anomalies(limit=None, since_iso=None):
    if os.path.exists(ANOMALIES_CSV_PATH):
        df = pd.read_csv(ANOMALIES_CSV_PATH)
    else:
        df = pd.read_csv(CSV_PATH)
        if 'anomaly_label' in df.columns:
            df = df[df['anomaly_label'] == -1]
        else:
            df = df.head(0)
    if since_iso and 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df = df[df['timestamp'] >= pd.to_datetime(since_iso, errors='coerce')]
    if limit:
        df = df.head(limit)
    return df


def fetch_related_events(base_ts: str, agent: str | None, window_minutes: int = 15):
    try:
        ts = pd.to_datetime(base_ts, errors='coerce')
        if pd.isna(ts):
            return []
        start = (ts - pd.Timedelta(minutes=window_minutes)).isoformat() + 'Z'
        end = (ts + pd.Timedelta(minutes=window_minutes)).isoformat() + 'Z'

        must_clauses = [
            {"range": {"timestamp": {"gte": start, "lte": end}}}
        ]
        if agent:
            must_clauses.append({"term": {"agent.name": agent}})

        query = {
            "size": LLM_MAX_EVENTS,
            "query": {"bool": {"must": must_clauses}},
            "sort": [{"timestamp": "asc"}],
            "_source": [
                "timestamp", "agent.name", "rule.level", "rule.category", "rule.description",
                "data.proto", "data.src_ip", "data.src_port", "data.dest_ip", "data.dest_port",
                "data.alert.signature", "data.alert.category", "syscheck.path", "syscheck.event"
            ]
        }

        url = f"{WAZUH_INDEXER_URL}/{WAZUH_INDEX_PATTERN}/_search"
        resp = requests.post(url, auth=(INDEXER_USER, INDEXER_PASS), json=query, verify=get_requests_verify(), timeout=30)
        resp.raise_for_status()
        hits = resp.json().get('hits', {}).get('hits', [])

        events = []
        for h in hits:
            s = h.get('_source', {})
            data = s.get('data', {}) or {}
            alert = data.get('alert', {}) if isinstance(data.get('alert'), dict) else {}
            syscheck = s.get('syscheck', {}) if isinstance(s.get('syscheck'), dict) else {}
            
            events.append({
                'timestamp': s.get('timestamp'),
                'agent': s.get('agent', {}).get('name'),
                'rule_level': s.get('rule', {}).get('level'),
                'rule_category': s.get('rule', {}).get('category'),
                'event_desc': s.get('rule', {}).get('description'),
                'src_ip': data.get('src_ip') or data.get('srcip'),
                'dst_ip': data.get('dest_ip') or data.get('destip') or data.get('dst_ip') or data.get('dstip'),
                'src_port': data.get('src_port') or data.get('srcport'),
                'dst_port': data.get('dest_port') or data.get('destport') or data.get('dst_port') or data.get('dstport'),
                'proto': data.get('proto') or data.get('protocol'),
                'alert_signature': alert.get('signature'),
                'alert_category': alert.get('category'),
                'syscheck_path': syscheck.get('path'),
                'syscheck_event': syscheck.get('event'),
            })
        return events
    except Exception:
        return []


def summarize_context(events: list[dict]) -> dict:
    if not events:
        return {"count": 0, "by_category": {}, "top_messages": [], "unique_ips": []}
    df = pd.DataFrame(events)
    out = {"count": len(df)}
    if 'rule_category' in df.columns:
        out["by_category"] = df['rule_category'].value_counts().head(10).to_dict()
    if 'event_desc' in df.columns:
        top_msgs = df['event_desc'].value_counts().head(10)
        out["top_messages"] = [(str(k)[:80], int(v)) for k, v in top_msgs.items()]
    ips = set()
    for col in ['src_ip', 'dst_ip']:
        if col in df.columns:
            ips.update([str(x) for x in df[col].dropna().unique()[:20]])
    out["unique_ips"] = list(ips)
    return out


def build_prompt(anomaly_row: pd.Series, context_summary: dict) -> str:
    header = (
        "You are a SOC analyst. Analyze the anomaly and produce: Summary, Likely Root Cause, "
        "False-Positive Risk, Evidence (specific indicators), and Recommended Actions. Be concise.\n"
    )
    anomaly = anomaly_row.fillna("")
    anomaly_text = json.dumps(anomaly.to_dict(), ensure_ascii=False)
    context_text = json.dumps(context_summary, ensure_ascii=False)
    return f"{header}\nANOMALY:\n{anomaly_text}\n\nRELATED CONTEXT SUMMARY:\n{context_text}\n"


def write_report(out_dir: str, anomaly_idx: int, text: str, anomaly_row: pd.Series):
    os.makedirs(out_dir, exist_ok=True)
    # Use current date/time for filename
    now = datetime.now()
    safe_id = f"{anomaly_idx}_{now.strftime('%Y-%m-%d %H-%M-%S')}"
    path = os.path.join(out_dir, f"report_{safe_id}.md")
    
    # Ensure text is not empty
    if not text or not text.strip():
        text = "[LLM ERROR: Empty response received]"
    
    with open(path, 'w', encoding='utf-8') as f:
        f.write(text)
    return path


def analyze_anomalies(
    since_iso: str = None,
    limit: int = 10,
    window_minutes: int = 15,
    post_alert: bool = False,
    out_dir: str = "data/anomaly_reports"
):
    """
    Phân tích anomalies bằng LLM
    
    Args:
        since_iso: ISO time để filter anomalies từ thời điểm này
        limit: Số lượng anomalies tối đa để phân tích
        window_minutes: Số phút window để tìm related events
        post_alert: Có post alert lên Wazuh không
        out_dir: Thư mục output cho reports
    """
    anomalies = read_anomalies(limit=limit, since_iso=since_iso)
    if anomalies.empty:
        print("No anomalies to analyze.")
        return

    for i, row in anomalies.iterrows():
        base_ts = row.get('timestamp', None)
        agent = row.get('agent', None)
        related = fetch_related_events(base_ts, agent, window_minutes=window_minutes)
        summary = summarize_context(related)
        prompt = build_prompt(row, summary)
        
        print(f"Analyzing anomaly {i+1}/{len(anomalies)}...")
        result = call_llm_provider(prompt, system_prompt="You are a helpful SOC analyst.")
        
        if not result or not result.strip():
            print(f"  Warning: Empty response from LLM for anomaly {i}")
            result = "[LLM ERROR: Empty response received]"
        
        report_path = write_report(out_dir, i, result, row)
        print(f"  Saved report → {report_path}")

        if post_alert:
            short = result.splitlines()[0][:480]
            print(f"[LLM SUMMARY] {short}")


