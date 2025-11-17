"""
Visualization Module
Tạo các biểu đồ để phân tích model performance và data
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import confusion_matrix, classification_report, roc_curve, auc
from sklearn.preprocessing import label_binarize
import os
from typing import Optional, List, Dict, Tuple

sns.set_style("whitegrid")
plt.rcParams.update({"figure.figsize": (12, 8), "font.size": 10})

VISUALIZATION_DIR = "data/visualizations"
os.makedirs(VISUALIZATION_DIR, exist_ok=True)


def _save(fig, path, default):
    path = path or os.path.join(VISUALIZATION_DIR, default)
    fig.savefig(path, dpi=300, bbox_inches="tight")
    print(f"  Saved plot → {path}")
    plt.close(fig)


def _bar_plot(labels, values, *, horizontal=False, title="", xlabel="", ylabel="", fmt="{:.3f}", save=None):
    fig, ax = plt.subplots(figsize=(max(10, len(labels) * 0.5), 6))
    positions = range(len(labels))
    colors = plt.cm.viridis(np.linspace(0, 1, len(labels)))
    bars = (ax.barh if horizontal else ax.bar)(positions, values, color=colors)
    (ax.set_yticks if horizontal else ax.set_xticks)(positions)
    (ax.set_yticklabels if horizontal else ax.set_xticklabels)(labels, rotation=45 if not horizontal else 0, ha="right")
    ax.set_title(title, fontsize=14, fontweight="bold")
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=12, fontweight="bold")
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=12, fontweight="bold")
    for pos, val in zip(bars, values):
        coord = (pos.get_width(), pos.get_y() + pos.get_height() / 2) if horizontal else (pos.get_x() + pos.get_width() / 2, pos.get_height())
        ax.text(*coord, f" {fmt.format(val)}", va="center" if horizontal else "bottom", ha="left" if horizontal else "center", fontsize=9)
    plt.tight_layout()
    _save(fig, save, f"{title.lower().replace(' ', '_')}.png")


def plot_feature_importance(feature_names: List[str], importances: np.ndarray, top_n: int = 20, save_path: Optional[str] = None):
    df = pd.DataFrame({"feature": feature_names, "importance": importances}).nlargest(top_n, "importance")
    _bar_plot(df["feature"].tolist(), df["importance"].tolist(), horizontal=True, title=f"Top {top_n} Features", xlabel="Importance", save=save_path or os.path.join(VISUALIZATION_DIR, "feature_importance.png"))


def plot_confusion_matrix(y_true, y_pred, class_names, normalize=True, save_path=None):
    cm = confusion_matrix(y_true, y_pred, labels=range(len(class_names))).astype(float)
    data = cm / cm.sum(axis=1, keepdims=True) if normalize else cm
    fig, ax = plt.subplots(figsize=(max(10, len(class_names) * 0.8), max(8, len(class_names) * 0.7)))
    sns.heatmap(
        data,
        annot=True,
        fmt=".2f" if normalize else "d",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        ax=ax,
        cbar_kws={"label": "Proportion" if normalize else "Count"},
    )
    ax.set(xlabel="Predicted", ylabel="True", title="Normalized Confusion Matrix" if normalize else "Confusion Matrix")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    suffix = "normalized" if normalize else "count"
    _save(fig, save_path, f"confusion_matrix_{suffix}.png")


def plot_classification_report(y_true, y_pred, class_names, save_path=None):
    report_df = pd.DataFrame(classification_report(y_true, y_pred, target_names=class_names, output_dict=True, zero_division=0)).T
    report_df = report_df.loc[class_names, ["precision", "recall", "f1-score"]]
    fig, ax = plt.subplots(figsize=(10, max(6, len(class_names) * 0.5)))
    sns.heatmap(report_df, annot=True, fmt=".3f", cmap="YlOrRd", vmin=0, vmax=1, ax=ax, cbar_kws={"label": "Score"})
    ax.set(xlabel="Metric", ylabel="Class", title="Classification Report")
    plt.tight_layout()
    _save(fig, save_path, "classification_report.png")


def plot_class_distribution(y, class_names, title="Class Distribution", save_path=None):
    counts = pd.Series(y).value_counts().reindex(range(len(class_names)), fill_value=0)
    labels = [class_names[i] for i in counts.index]
    _bar_plot(labels, counts.values, title=title, ylabel="Count", save=save_path or os.path.join(VISUALIZATION_DIR, "class_distribution.png"))


def plot_roc_curves(y_true, y_proba, class_names, save_path=None):
    y_bin = label_binarize(y_true, classes=range(len(class_names)))
    fig, ax = plt.subplots(figsize=(10, 8))
    for idx, name in enumerate(class_names):
        fpr, tpr, _ = roc_curve(y_bin[:, idx], y_proba[:, idx])
        ax.plot(fpr, tpr, lw=2, label=f"{name} (AUC={auc(fpr, tpr):.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=2, label="Random")
    ax.set(xlabel="False Positive Rate", ylabel="True Positive Rate", title="ROC Curves")
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(alpha=0.3)
    plt.tight_layout()
    _save(fig, save_path, "roc_curves.png")


def plot_model_comparison(model_names, metrics, save_path=None):
    fig, axes = plt.subplots(1, len(metrics), figsize=(6 * len(metrics), 6))
    axes = [axes] if len(metrics) == 1 else axes
    for ax, (metric, values) in zip(axes, metrics.items()):
        bars = ax.bar(model_names, values, color=plt.cm.viridis(np.linspace(0, 1, len(model_names))))
        ax.set(title=f"{metric} Comparison", ylabel=metric)
        ax.set_ylim(0, max(values) * 1.1 if values else 1)
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width() / 2, val, f"{val:.3f}", ha="center", va="bottom", fontsize=10)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right")
    plt.tight_layout()
    _save(fig, save_path, "model_comparison.png")


def plot_feature_correlation(X: pd.DataFrame, top_n: int = 30, save_path: Optional[str] = None):
    subset = X[X.var().sort_values(ascending=False).head(top_n).index] if len(X.columns) > top_n else X
    fig, ax = plt.subplots(figsize=(max(12, len(subset.columns) * 0.4), max(10, len(subset.columns) * 0.4)))
    sns.heatmap(subset.corr(), cmap="coolwarm", center=0, square=True, ax=ax, cbar_kws={"label": "Correlation"})
    ax.set_title(f"Feature Correlation ({len(subset.columns)} features)")
    plt.xticks(rotation=90, fontsize=8)
    plt.yticks(rotation=0, fontsize=8)
    plt.tight_layout()
    _save(fig, save_path, "feature_correlation.png")


def create_training_visualizations(
    y_train,
    y_test,
    y_pred_train,
    y_pred_test,
    y_proba_test,
    class_names,
    feature_names=None,
    feature_importances=None,
    model_name="Model",
):
    print("\n" + "=" * 60)
    print(f"Creating Visualizations for {model_name}")
    print("=" * 60)

    plot_class_distribution(np.concatenate([y_train, y_test]), class_names, title=f"{model_name} - Class Distribution")

    if feature_names is not None and feature_importances is not None:
        plot_feature_importance(feature_names, feature_importances)

    for normalize in (True, False):
        plot_confusion_matrix(y_test, y_pred_test, class_names, normalize=normalize)

    plot_classification_report(y_test, y_pred_test, class_names)

    if y_proba_test is not None:
        try:
            plot_roc_curves(y_test, y_proba_test, class_names)
        except Exception as exc:
            print(f"  Warning: Could not plot ROC curves: {exc}")

    print(f"\nAll visualizations saved to: {VISUALIZATION_DIR}\n")

