import sys
import os
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)


def export_logs():
    """Export logs từ Wazuh Indexer"""
    print("=" * 70)
    print("EXPORTING LOGS FROM WAZUH INDEXER")
    print("=" * 70)
    from data_processing.export_from_es import fetch_logs
    fetch_logs()


def train_anomaly_model(enable_tuning=True):
    """Train anomaly detection model"""
    print("=" * 70)
    print("TRAINING ANOMALY DETECTION MODEL")
    print("=" * 70)
    from training.train_model import train_model_with_tuning
    train_model_with_tuning(enable_tuning=enable_tuning)


def train_classifier(enable_tuning=True):
    """Train classification model"""
    print("=" * 70)
    print("TRAINING CLASSIFICATION MODEL")
    print("=" * 70)
    from training.train_classifier import train_classification_models
    train_classification_models(enable_tuning=enable_tuning)


def train_all_models(enable_tuning=True):
    """Train cả anomaly detection và classification models"""
    print("=" * 70)
    print("TRAINING ALL MODELS")
    print("=" * 70)
    from training.train_all_models import train_all
    train_all(enable_tuning=enable_tuning)


def detect_anomalies():
    """Phát hiện anomalies"""
    print("=" * 70)
    print("DETECTING ANOMALIES")
    print("=" * 70)
    from detection.detect_anomaly import detect
    detect()


def classify_events():
    """Phân loại events"""
    print("=" * 70)
    print("CLASSIFYING EVENTS")
    print("=" * 70)
    from classification.classify_events import classify
    classify()


def realtime_detection():
    """Real-time anomaly detection"""
    print("=" * 70)
    print("STARTING REAL-TIME DETECTION")
    print("=" * 70)
    from detection.realtime_detector import RealtimeDetector
    detector = RealtimeDetector()
    try:
        detector.start()
    except KeyboardInterrupt:
        print("\n\nĐã dừng real-time detection")


def evaluate_models():
    """Đánh giá models"""
    print("=" * 70)
    print("EVALUATING MODELS")
    print("=" * 70)
    from utils.evaluate import main as evaluate_main
    evaluate_main()


def llm_analyze():
    """Phân tích anomalies bằng LLM"""
    print("=" * 70)
    print("LLM ANALYSIS")
    print("=" * 70)
    from llm.llm_analyze import main as llm_main
    llm_main()


def show_menu():
    """Hiển thị menu chọn chức năng"""
    print("\n" + "=" * 70)
    print("WAZUH ML - SECURITY ANALYTICS")
    print("=" * 70)
    print("\nChọn chức năng:")
    print("  1. Export logs từ Wazuh Indexer")
    print("  2. Train anomaly detection model")
    print("  3. Train classification model")
    print("  4. Train cả 2 models")
    print("  5. Detect anomalies")
    print("  6. Classify events")
    print("  7. Real-time detection")
    print("  8. Evaluate models")
    print("  9. LLM analysis")
    print("  0. Thoát")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Wazuh ML - Security Analytics System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py export              # Export logs
  python main.py train-all           # Train cả 2 models
  python main.py detect              # Detect anomalies
  python main.py --menu              # Hiển thị menu tương tác
        """
    )
    
    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "export", "train", "train-classifier", "train-all",
            "detect", "classify", "realtime", "evaluate", "llm"
        ],
        help="Command to run"
    )
    parser.add_argument(
        "--menu", "-m",
        action="store_true",
        help="Hiển thị menu tương tác"
    )
    parser.add_argument(
        "--no-tuning",
        action="store_true",
        help="Disable hyperparameter tuning (chỉ cho train commands)"
    )
    
    args = parser.parse_args()
    
    # Nếu có --menu hoặc không có command, hiển thị menu
    if args.menu or not args.command:
        while True:
            show_menu()
            try:
                choice = input("\nNhập lựa chọn (0-9): ").strip()
                
                if choice == "0":
                    print("\nTạm biệt!")
                    break
                elif choice == "1":
                    export_logs()
                elif choice == "2":
                    train_anomaly_model(enable_tuning=not args.no_tuning)
                elif choice == "3":
                    train_classifier(enable_tuning=not args.no_tuning)
                elif choice == "4":
                    train_all_models(enable_tuning=not args.no_tuning)
                elif choice == "5":
                    detect_anomalies()
                elif choice == "6":
                    classify_events()
                elif choice == "7":
                    realtime_detection()
                elif choice == "8":
                    evaluate_models()
                elif choice == "9":
                    llm_analyze()
                else:
                    print("Lựa chọn không hợp lệ! Vui lòng chọn từ 0-9.")
                
                if choice != "0":
                    input("\n⏸Nhấn Enter để tiếp tục...")
                    
            except KeyboardInterrupt:
                print("\n\nạm biệt!")
                break
            except EOFError:
                print("\n\nTạm biệt!")
                break
    else:
        # Chạy command trực tiếp
        if args.command == "export":
            export_logs()
        elif args.command == "train":
            train_anomaly_model(enable_tuning=not args.no_tuning)
        elif args.command == "train-classifier":
            train_classifier(enable_tuning=not args.no_tuning)
        elif args.command == "train-all":
            train_all_models(enable_tuning=not args.no_tuning)
        elif args.command == "detect":
            detect_anomalies()
        elif args.command == "classify":
            classify_events()
        elif args.command == "realtime":
            realtime_detection()
        elif args.command == "evaluate":
            evaluate_models()
        elif args.command == "llm":
            llm_analyze()


if __name__ == "__main__":
    main()

