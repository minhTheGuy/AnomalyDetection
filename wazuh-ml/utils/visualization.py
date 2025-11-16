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
from sklearn.multiclass import OneVsRestClassifier
import os
from typing import Optional, List, Dict, Tuple

# Set style
sns.set_style("whitegrid")
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 10

# Create output directory
VISUALIZATION_DIR = "data/visualizations"
os.makedirs(VISUALIZATION_DIR, exist_ok=True)


def plot_feature_importance(
    feature_names: List[str],
    importances: np.ndarray,
    top_n: int = 20,
    save_path: Optional[str] = None
):
    """
    Vẽ biểu đồ feature importance
    
    Args:
        feature_names: Tên các features
        importances: Feature importance values
        top_n: Số features top để hiển thị
        save_path: Đường dẫn để lưu (None = auto)
    """
    # Tạo DataFrame
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': importances
    }).sort_values('importance', ascending=False)
    
    # Lấy top N
    top_features = importance_df.head(top_n)
    
    # Vẽ biểu đồ
    fig, ax = plt.subplots(figsize=(12, max(8, top_n * 0.4)))
    colors = plt.cm.viridis(np.linspace(0, 1, len(top_features)))
    
    bars = ax.barh(range(len(top_features)), top_features['importance'], color=colors)
    ax.set_yticks(range(len(top_features)))
    ax.set_yticklabels(top_features['feature'])
    ax.set_xlabel('Feature Importance', fontsize=12, fontweight='bold')
    ax.set_title(f'Top {top_n} Most Important Features', fontsize=14, fontweight='bold')
    ax.invert_yaxis()
    
    # Thêm giá trị trên mỗi bar
    for i, (idx, row) in enumerate(top_features.iterrows()):
        ax.text(row['importance'], i, f' {row["importance"]:.4f}', 
                va='center', fontsize=9)
    
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'feature_importance.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved feature importance plot → {save_path}")
    plt.close()


def plot_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: List[str],
    normalize: bool = True,
    save_path: Optional[str] = None
):
    """
    Vẽ confusion matrix heatmap
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        class_names: Tên các classes
        normalize: Có normalize hay không
        save_path: Đường dẫn để lưu
    """
    cm = confusion_matrix(y_true, y_pred, labels=range(len(class_names)))
    
    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        fmt = '.2f'
        title = 'Normalized Confusion Matrix'
    else:
        fmt = 'd'
        title = 'Confusion Matrix'
    
    # Vẽ heatmap
    fig, ax = plt.subplots(figsize=(max(10, len(class_names) * 0.8), 
                                     max(8, len(class_names) * 0.7)))
    
    sns.heatmap(
        cm,
        annot=True,
        fmt=fmt,
        cmap='Blues',
        xticklabels=class_names,
        yticklabels=class_names,
        ax=ax,
        cbar_kws={'label': 'Proportion' if normalize else 'Count'}
    )
    
    ax.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Label', fontsize=12, fontweight='bold')
    ax.set_title(title, fontsize=14, fontweight='bold')
    
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    plt.tight_layout()
    
    if save_path is None:
        suffix = 'normalized' if normalize else 'count'
        save_path = os.path.join(VISUALIZATION_DIR, f'confusion_matrix_{suffix}.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved confusion matrix → {save_path}")
    plt.close()


def plot_classification_report(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: List[str],
    save_path: Optional[str] = None
):
    """
    Vẽ classification report dưới dạng heatmap
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        class_names: Tên các classes
        save_path: Đường dẫn để lưu
    """
    report = classification_report(
        y_true, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0
    )
    
    # Chuyển thành DataFrame (bỏ 'accuracy' và 'macro avg', 'weighted avg')
    metrics = ['precision', 'recall', 'f1-score']
    report_df = pd.DataFrame(report).T
    report_df = report_df[report_df.index.isin(class_names)][metrics]
    
    # Vẽ heatmap
    fig, ax = plt.subplots(figsize=(10, max(6, len(class_names) * 0.5)))
    
    sns.heatmap(
        report_df,
        annot=True,
        fmt='.3f',
        cmap='YlOrRd',
        ax=ax,
        cbar_kws={'label': 'Score'},
        vmin=0,
        vmax=1
    )
    
    ax.set_xlabel('Metric', fontsize=12, fontweight='bold')
    ax.set_ylabel('Class', fontsize=12, fontweight='bold')
    ax.set_title('Classification Report (Per-Class Metrics)', fontsize=14, fontweight='bold')
    
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'classification_report.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved classification report → {save_path}")
    plt.close()


def plot_class_distribution(
    y: np.ndarray,
    class_names: List[str],
    title: str = "Class Distribution",
    save_path: Optional[str] = None
):
    """
    Vẽ phân phối các classes
    
    Args:
        y: Labels
        class_names: Tên các classes
        title: Tiêu đề
        save_path: Đường dẫn để lưu
    """
    class_counts = pd.Series(y).value_counts()
    class_counts = class_counts.reindex(range(len(class_names)), fill_value=0)
    class_counts.index = [class_names[i] for i in class_counts.index]
    
    # Vẽ bar plot
    fig, ax = plt.subplots(figsize=(max(10, len(class_names) * 0.6), 6))
    
    colors = plt.cm.Set3(np.linspace(0, 1, len(class_counts)))
    bars = ax.bar(range(len(class_counts)), class_counts.values, color=colors)
    
    ax.set_xticks(range(len(class_counts)))
    ax.set_xticklabels(class_counts.index, rotation=45, ha='right')
    ax.set_ylabel('Count', fontsize=12, fontweight='bold')
    ax.set_title(title, fontsize=14, fontweight='bold')
    
    # Thêm giá trị trên mỗi bar
    for i, (bar, count) in enumerate(zip(bars, class_counts.values)):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f' {int(count)}',
                ha='center', va='bottom', fontsize=9)
    
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'class_distribution.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved class distribution → {save_path}")
    plt.close()


def plot_roc_curves(
    y_true: np.ndarray,
    y_proba: np.ndarray,
    class_names: List[str],
    save_path: Optional[str] = None
):
    """
    Vẽ ROC curves cho multi-class classification
    
    Args:
        y_true: True labels (encoded)
        y_proba: Predicted probabilities
        class_names: Tên các classes
        save_path: Đường dẫn để lưu
    """
    n_classes = len(class_names)
    
    # Binarize labels
    y_true_bin = label_binarize(y_true, classes=range(n_classes))
    
    # Tính ROC cho mỗi class
    fpr = dict()
    tpr = dict()
    roc_auc = dict()
    
    for i in range(n_classes):
        fpr[i], tpr[i], _ = roc_curve(y_true_bin[:, i], y_proba[:, i])
        roc_auc[i] = auc(fpr[i], tpr[i])
    
    # Vẽ ROC curves
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = plt.cm.rainbow(np.linspace(0, 1, n_classes))
    
    for i, color in zip(range(n_classes), colors):
        ax.plot(fpr[i], tpr[i], color=color, lw=2,
                label=f'{class_names[i]} (AUC = {roc_auc[i]:.3f})')
    
    ax.plot([0, 1], [0, 1], 'k--', lw=2, label='Random')
    ax.set_xlim([0.0, 1.0])
    ax.set_ylim([0.0, 1.05])
    ax.set_xlabel('False Positive Rate', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Positive Rate', fontsize=12, fontweight='bold')
    ax.set_title('ROC Curves (Multi-Class)', fontsize=14, fontweight='bold')
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(alpha=0.3)
    
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'roc_curves.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved ROC curves → {save_path}")
    plt.close()


def plot_model_comparison(
    model_names: List[str],
    metrics: Dict[str, List[float]],
    save_path: Optional[str] = None
):
    """
    So sánh performance của nhiều models
    
    Args:
        model_names: Tên các models
        metrics: Dictionary với metric names và values
        save_path: Đường dẫn để lưu
    """
    n_metrics = len(metrics)
    fig, axes = plt.subplots(1, n_metrics, figsize=(6 * n_metrics, 6))
    
    if n_metrics == 1:
        axes = [axes]
    
    for idx, (metric_name, values) in enumerate(metrics.items()):
        ax = axes[idx]
        bars = ax.bar(model_names, values, color=plt.cm.viridis(np.linspace(0, 1, len(model_names))))
        ax.set_ylabel(metric_name, fontsize=12, fontweight='bold')
        ax.set_title(f'{metric_name} Comparison', fontsize=14, fontweight='bold')
        ax.set_ylim([0, max(values) * 1.1])
        
        # Thêm giá trị trên mỗi bar
        for bar, val in zip(bars, values):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                    f' {val:.3f}',
                    ha='center', va='bottom', fontsize=10)
        
        plt.setp(ax.xaxis.get_majorticklabels(), rotation=45, ha='right')
    
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'model_comparison.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved model comparison → {save_path}")
    plt.close()


def plot_feature_correlation(
    X: pd.DataFrame,
    top_n: int = 30,
    save_path: Optional[str] = None
):
    """
    Vẽ correlation matrix của các features
    
    Args:
        X: Feature matrix
        top_n: Số features top để hiển thị (dựa trên variance)
        save_path: Đường dẫn để lưu
    """
    # Chọn top N features có variance cao nhất
    if len(X.columns) > top_n:
        variances = X.var().sort_values(ascending=False)
        top_features = variances.head(top_n).index.tolist()
        X_subset = X[top_features]
    else:
        X_subset = X
    
    # Tính correlation
    corr = X_subset.corr()
    
    # Vẽ heatmap
    fig, ax = plt.subplots(figsize=(max(12, top_n * 0.4), max(10, top_n * 0.4)))
    
    sns.heatmap(
        corr,
        annot=False,
        cmap='coolwarm',
        center=0,
        square=True,
        ax=ax,
        cbar_kws={'label': 'Correlation'}
    )
    
    ax.set_title(f'Feature Correlation Matrix (Top {len(X_subset.columns)} Features)', 
                 fontsize=14, fontweight='bold')
    
    plt.xticks(rotation=90, fontsize=8)
    plt.yticks(rotation=0, fontsize=8)
    plt.tight_layout()
    
    if save_path is None:
        save_path = os.path.join(VISUALIZATION_DIR, 'feature_correlation.png')
    
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    print(f"  Saved feature correlation → {save_path}")
    plt.close()


def create_training_visualizations(
    y_train: np.ndarray,
    y_test: np.ndarray,
    y_pred_train: np.ndarray,
    y_pred_test: np.ndarray,
    y_proba_test: Optional[np.ndarray],
    class_names: List[str],
    feature_names: Optional[List[str]] = None,
    feature_importances: Optional[np.ndarray] = None,
    model_name: str = "Model"
):
    """
    Tạo tất cả visualizations cho training results
    
    Args:
        y_train: Training labels
        y_test: Test labels
        y_pred_train: Training predictions
        y_pred_test: Test predictions
        y_proba_test: Test probabilities (optional)
        class_names: Tên các classes
        feature_names: Tên các features (optional)
        feature_importances: Feature importances (optional)
        model_name: Tên model
    """
    print(f"\n{'='*60}")
    print(f"Creating Visualizations for {model_name}")
    print(f"{'='*60}")
    
    # 1. Class distribution
    print("\n1. Plotting class distribution...")
    plot_class_distribution(
        np.concatenate([y_train, y_test]),
        class_names,
        title=f"{model_name} - Class Distribution"
    )
    
    # 2. Feature importance
    if feature_names is not None and feature_importances is not None:
        print("\n2. Plotting feature importance...")
        plot_feature_importance(feature_names, feature_importances)
    
    # 3. Confusion matrix (normalized)
    print("\n3. Plotting confusion matrix...")
    plot_confusion_matrix(
        y_test, y_pred_test, class_names,
        normalize=True
    )
    
    # 4. Confusion matrix (count)
    plot_confusion_matrix(
        y_test, y_pred_test, class_names,
        normalize=False
    )
    
    # 5. Classification report
    print("\n4. Plotting classification report...")
    plot_classification_report(
        y_test, y_pred_test, class_names
    )
    
    # 6. ROC curves (nếu có probabilities)
    if y_proba_test is not None:
        print("\n5. Plotting ROC curves...")
        try:
            plot_roc_curves(y_test, y_proba_test, class_names)
        except Exception as e:
            print(f"  Warning: Could not plot ROC curves: {e}")
    
    print(f"\n{'='*60}")
    print(f"All visualizations saved to: {VISUALIZATION_DIR}")
    print(f"{'='*60}\n")

