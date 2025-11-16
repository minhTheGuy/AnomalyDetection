# Visualization Module

## 📊 Tổng Quan

Module visualization tạo các biểu đồ để phân tích model performance và data distribution.

## 🎨 Các Visualizations

### 1. **Feature Importance Plot**
- Hiển thị top N features quan trọng nhất
- Giúp hiểu model đang dùng features nào
- File: `data/visualizations/feature_importance.png`

### 2. **Confusion Matrix**
- Normalized confusion matrix (tỷ lệ)
- Count confusion matrix (số lượng)
- Giúp xem model nhầm lẫn giữa các classes nào
- Files: 
  - `data/visualizations/confusion_matrix_normalized.png`
  - `data/visualizations/confusion_matrix_count.png`

### 3. **Classification Report**
- Heatmap với precision, recall, f1-score cho mỗi class
- Dễ so sánh performance giữa các classes
- File: `data/visualizations/classification_report.png`

### 4. **Class Distribution**
- Phân phối số lượng samples của mỗi class
- Giúp phát hiện class imbalance
- File: `data/visualizations/class_distribution.png`

### 5. **ROC Curves**
- ROC curves cho multi-class classification
- Hiển thị AUC cho mỗi class
- File: `data/visualizations/roc_curves.png`

### 6. **Feature Correlation Matrix**
- Correlation giữa các features
- Giúp phát hiện multicollinearity
- File: `data/visualizations/feature_correlation.png`

### 7. **Model Comparison**
- So sánh performance của nhiều models
- File: `data/visualizations/model_comparison.png`

## 🚀 Sử Dụng

### Tự Động (Khi Training)

Visualizations được tạo tự động khi train classification model:

```bash
python main.py train-classifier
```

Tất cả visualizations sẽ được lưu vào `data/visualizations/`

### Thủ Công

```python
from utils.visualization import (
    plot_feature_importance,
    plot_confusion_matrix,
    plot_classification_report,
    plot_class_distribution,
    plot_roc_curves,
    create_training_visualizations
)

# Tạo tất cả visualizations
create_training_visualizations(
    y_train=y_train,
    y_test=y_test,
    y_pred_train=y_pred_train,
    y_pred_test=y_pred_test,
    y_proba_test=y_proba_test,
    class_names=class_names,
    feature_names=feature_names,
    feature_importances=feature_importances,
    model_name="My Model"
)
```

## ⚙️ Cấu Hình

Trong `training/train_classifier.py`:

```python
ENABLE_VISUALIZATION = True  # Set False để tắt
```

## 📁 Output Directory

Tất cả visualizations được lưu trong:
```
data/visualizations/
├── feature_importance.png
├── confusion_matrix_normalized.png
├── confusion_matrix_count.png
├── classification_report.png
├── class_distribution.png
├── roc_curves.png
└── feature_correlation.png
```

## 📦 Dependencies

```bash
pip install matplotlib seaborn
```

## 🎯 Use Cases

1. **Model Evaluation**: Xem model performance chi tiết
2. **Feature Analysis**: Hiểu features nào quan trọng
3. **Class Imbalance**: Phát hiện và xử lý class imbalance
4. **Error Analysis**: Xem model nhầm lẫn giữa classes nào
5. **Model Comparison**: So sánh nhiều models

## 💡 Tips

- Visualizations được tạo với DPI 300, phù hợp cho báo cáo
- Tất cả plots có title và labels rõ ràng
- Colors được chọn để dễ phân biệt
- Layout tự động điều chỉnh theo số lượng classes/features

