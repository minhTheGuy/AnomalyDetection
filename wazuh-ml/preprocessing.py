# preprocessing.py
import pandas as pd
from sklearn.preprocessing import LabelEncoder

def preprocess_dataframe(df: pd.DataFrame):
    # dọn sạch
    df = df.dropna(subset=["event_desc"]).copy()

    # ép kiểu cổng thành số
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")

    # ensure string
    df["agent"] = df["agent"].astype(str)
    df["event_desc"] = df["event_desc"].astype(str)

    # encode categorical
    enc_event = LabelEncoder()
    df["event_code"] = enc_event.fit_transform(df["event_desc"])

    enc_agent = LabelEncoder()
    df["agent_code"] = enc_agent.fit_transform(df["agent"])

    # chọn features cho ML
    feature_cols = ["src_port", "dst_port", "event_code", "agent_code"]
    X = df[feature_cols].fillna(0)

    return df, X, enc_event, enc_agent
