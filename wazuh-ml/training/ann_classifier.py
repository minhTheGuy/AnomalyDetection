"""
Keras-based binary classifier
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.keras import layers


DEFAULT_PARAMS: Dict[str, object] = {
    "hidden_units": [256, 128, 64],
    "dropout": 0.3,
    "learning_rate": 1e-3,
    "batch_size": 1024,
    "epochs": 100,
    "test_size": 0.2,
    "random_state": 42,
    "early_stopping_patience": 10,
    "decision_threshold": 0.5,
}


@dataclass
class ANNTrainingResult:
    model_path: str
    scaler: StandardScaler
    history: Dict[str, List[float]]
    metrics: Dict[str, float]
    decision_threshold: float


def _build_ann_model(
    input_dim: int,
    hidden_units: List[int],
    dropout: float,
    learning_rate: float,
) -> keras.Model:
    model = keras.Sequential()
    model.add(keras.Input(shape=(input_dim,)))
    for units in hidden_units:
        model.add(layers.Dense(units, activation="relu"))
        model.add(layers.BatchNormalization())
        model.add(layers.Dropout(dropout))
    model.add(layers.Dense(1, activation="sigmoid"))

    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=learning_rate),
        loss="binary_crossentropy",
        metrics=[
            keras.metrics.BinaryAccuracy(name="accuracy"),
            keras.metrics.AUC(name="auc"),
            keras.metrics.Precision(name="precision"),
            keras.metrics.Recall(name="recall"),
        ],
    )

    return model


def train_binary_ann_classifier(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: List[str],
    *,
    model_output_path: str,
    params: Optional[Dict[str, object]] = None,
) -> ANNTrainingResult:
    """
    Train a binary ANN classifier using selected features.
    """

    params = {**DEFAULT_PARAMS, **(params or {})}

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_val, y_train, y_val = train_test_split(
        X_scaled,
        y,
        test_size=params["test_size"],
        random_state=params["random_state"],
        stratify=y,
    )

    model = _build_ann_model(
        input_dim=X_train.shape[1],
        hidden_units=params["hidden_units"],
        dropout=params["dropout"],
        learning_rate=params["learning_rate"],
    )

    callbacks: List[keras.callbacks.Callback] = [
        keras.callbacks.EarlyStopping(
            patience=params["early_stopping_patience"],
            restore_best_weights=True,
            monitor="val_loss",
        ),
        keras.callbacks.ReduceLROnPlateau(
            factor=0.5, patience=5, min_lr=1e-5, monitor="val_loss", verbose=1
        ),
    ]

    history = model.fit(
        X_train,
        y_train,
        validation_data=(X_val, y_val),
        epochs=params["epochs"],
        batch_size=params["batch_size"],
        verbose=2,
        callbacks=callbacks,
    )

    val_probs = model.predict(X_val, verbose=0).squeeze()
    threshold = params["decision_threshold"]
    val_preds = (val_probs >= threshold).astype(int)

    eval_metrics = model.evaluate(X_val, y_val, verbose=0, return_dict=True)

    metrics = {
        "accuracy": float(accuracy_score(y_val, val_preds)),
        "precision": float(precision_score(y_val, val_preds, zero_division=0)),
        "recall": float(recall_score(y_val, val_preds, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_val, val_probs)),
        "classification_report": classification_report(
            y_val,
            val_preds,
            target_names=["anomaly", "normal"],
            zero_division=0,
            output_dict=True,
        ),
        "eval_loss": float(eval_metrics.get("loss", 0.0)),
        "eval_accuracy": float(eval_metrics.get("accuracy", 0.0)),
    }

    model.save(model_output_path, overwrite=True)

    return ANNTrainingResult(
        model_path=model_output_path,
        scaler=scaler,
        history=history.history,
        metrics=metrics,
        decision_threshold=threshold,
    )

