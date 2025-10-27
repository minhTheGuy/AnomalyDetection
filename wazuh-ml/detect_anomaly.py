# detect_anomaly.py
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from preprocessing import preprocess_dataframe
from config import CSV_PATH, MODEL_PATH
import matplotlib.pyplot as plt


def detect():
    bundle = joblib.load(MODEL_PATH)
    model: IsolationForest = bundle["model"]
    enc_event = bundle["enc_event"]
    enc_agent = bundle["enc_agent"]

    # đọc log mới
    df_raw = pd.read_csv(CSV_PATH).copy()

    # giống preprocess_dataframe, nhưng phải dùng enc đã train,
    # không được fit lại vì làm vậy sẽ đổi mã event_code/agent_code
    df = df_raw.dropna(subset=["event_desc"]).copy()

    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    df["agent"] = df["agent"].astype(str)
    df["event_desc"] = df["event_desc"].astype(str)

    df["event_code"] = enc_event.transform(df["event_desc"])
    df["agent_code"] = enc_agent.transform(df["agent"])

    X = df[["src_port","dst_port","event_code","agent_code"]].fillna(0)

    df["anomaly_label"] = model.predict(X)
    df["anomaly_score"] = model.decision_function(X)

    anomalies = df[df["anomaly_label"] == -1]
    print("🔎 Số sự kiện bất thường:", len(anomalies))
    print(anomalies[["timestamp","agent","event_desc","src_ip","dst_ip","anomaly_score"]].head(20))

    plt.hist(df["anomaly_score"], bins=50)
    plt.title("Phân bố điểm bất thường")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Số lượng")
    plt.show()


if __name__ == "__main__":
    detect()
