from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from data_processing.export_from_es import fetch_logs as fetch_logs_from_wazuh
from detection.detect_anomaly import detect as detect_anomalies_from_wazuh

app = FastAPI(title="AnomalyDetection API")

class LogBatch(BaseModel):
    logs: List[dict]
    score_threshold: Optional[float] = None

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/fetch-logs")
def fetch_logs(limit: int = 1000):
    try:
        print('abc')
        records = fetch_logs_from_wazuh(limit=limit)
        return {"count": len(records), "logs": records}
    except Exception as e:
        print("ERROR in fetch_logs:", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/detect-anomalies")
def detect(batch: LogBatch):
    """
    Nhận batch logs, trả về anomalies + score.
    """
    anomalies = detect_anomalies_from_wazuh(
        batch.logs,
    )
    return {"count": len(anomalies), "anomalies": anomalies}
