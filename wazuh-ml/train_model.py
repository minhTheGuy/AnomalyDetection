# train_model.py
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from config import CSV_PATH, MODEL_PATH, ANALYZED_CSV_PATH
from preprocessing import preprocess_dataframe

def train_model():
    df = pd.read_csv(CSV_PATH)
    df, X, enc_event, enc_agent = preprocess_dataframe(df)

    model = IsolationForest(
        contamination=0.05,
        random_state=42
    )
    model.fit(X)

    # chấm điểm trên dữ liệu train (để xem thử)
    df["anomaly_label"] = model.predict(X)        # -1 = bất thường
    df["anomaly_score"] = model.decision_function(X)

    # lưu kết quả phân tích hiện tại (tham khảo)
    df.to_csv(ANALYZED_CSV_PATH, index=False)
    print(f"✅ Wrote analyzed data → {ANALYZED_CSV_PATH}")

    # lưu model để dùng lại
    joblib.dump({
        "model": model,
        "enc_event": enc_event,
        "enc_agent": enc_agent
    }, MODEL_PATH)
    print(f"✅ Saved model → {MODEL_PATH}")

if __name__ == "__main__":
    train_model()
