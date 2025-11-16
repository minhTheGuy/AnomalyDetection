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


def generate_synthetic_data(num_events=5000, benign_ratio=0.7, days=7, output=None, csv_output=None):
    """Generate synthetic training data"""
    print_header("GENERATING SYNTHETIC DATA")
    from data_processing.generate_synthetic_data import generate_synthetic_data as gen_data
    from datetime import datetime, timedelta
    
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)
    
    gen_data(
        num_events=num_events,
        start_date=start_date,
        end_date=end_date,
        benign_ratio=benign_ratio,
        output_path=output,
        csv_output_path=csv_output
    )


def run_tests(test_module=None):
    """Run test suite"""
    print_header("RUNNING TESTS")
    from tests.run_tests import run_all_tests, run_specific_test
    import sys
    
    if test_module:
        success = run_specific_test(test_module)
    else:
        success = run_all_tests()
    
    if success:
        print("\n  Tất cả tests đều đã pass!")
    else:
        print("\nMột số tests đã fail!")
        sys.exit(1)


def check_threat_intelligence(ip=None, file_hash=None):
    """Kiểm tra threat intelligence feeds"""
    print_header("KIỂM TRA THÔNG TIN AN TOÀN")
    from threat_intelligence.feeds import get_threat_intel_manager
    
    manager = get_threat_intel_manager()
    
    if ip:
        print(f"\nChecking IP: {ip}")
        is_malicious = manager.is_malicious_ip(ip)
        print(f"  Malicious: {is_malicious}")
        
        # Check AbuseIPDB nếu có
        for feed in manager.feeds:
            if hasattr(feed, 'check_ip'):
                result = feed.check_ip(ip)
                if result.get('abuse_confidence', 0) > 0:
                    print(f"  AbuseIPDB Confidence: {result['abuse_confidence']}%")
                    print(f"  Country: {result.get('country', 'N/A')}")
                    print(f"  Usage Type: {result.get('usage_type', 'N/A')}")
    
    if file_hash:
        print(f"\nChecking File Hash: {file_hash}")
        is_malicious = manager.is_malicious_hash(file_hash)
        print(f"  Malicious: {is_malicious}")
        
        # Check VirusTotal nếu có
        for feed in manager.feeds:
            if hasattr(feed, 'check_hash'):
                result = feed.check_hash(file_hash)
                if result.get('detected'):
                    print(f"  VirusTotal Positives: {result['positives']}/{result['total']}")
                    print(f"  Scan Date: {result.get('scan_date', 'N/A')}")


def run_transfer_learning(source_model=None, contamination=0.05, use_ensemble=True):
    """Bootstrap model với Transfer Learning"""
    print_header("TRANSFER LEARNING")
    from training.transfer_learning import bootstrap_with_transfer_learning
    from core.config import CSV_PATH, MODEL_PATH
    
    success = bootstrap_with_transfer_learning(
        target_data_path=CSV_PATH,
        source_model_path=source_model,
        output_model_path=MODEL_PATH,
        contamination=contamination,
        use_ensemble=use_ensemble
    )
    
    if success:
        print("\n  Transfer learning completed successfully!")
    else:
        print("\n  Transfer learning failed!")
        import sys
        sys.exit(1)


def run_feedback_loop(iterations=1, detect_only=False, retrain=True, run_tests=True):
    """Chạy Feedback Loop hoàn chỉnh"""
    print_header("FEEDBACK LOOP")
    from training.feedback_loop import run_feedback_loop
    
    results = run_feedback_loop(
        iterations=iterations,
        detect_only=detect_only,
        retrain=retrain,
        run_tests=run_tests
    )
    
    print(f"\n  Completed {len(results)} feedback loop iteration(s)")
    return results


def generate_actions(anomalies_csv=None, execute=False):
    """Generate và execute actions từ anomalies"""
    print_header("ACTION GENERATION & EXECUTION")
    from actions.action_manager import ActionManager
    from core.config import (
        ANOMALIES_CSV_PATH, ACTIONS_CSV_PATH, ACTION_RESULTS_CSV_PATH,
        ENABLE_AUTO_BLOCK, ENABLE_TELEGRAM, TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID,
        MIN_SEVERITY_FOR_BLOCK, MIN_SEVERITY_FOR_NOTIFY
    )
    import pandas as pd
    
    anomalies_path = anomalies_csv or ANOMALIES_CSV_PATH
    
    if not os.path.exists(anomalies_path):
        print(f"  Anomalies file not found: {anomalies_path}")
        print("   Please run 'detect' command first to generate anomalies.")
        return
    
    print(f"Reading anomalies from: {anomalies_path}")
    anomalies_df = pd.read_csv(anomalies_path)
    print(f"  Loaded {len(anomalies_df)} anomalies")
    
    # Action config
    action_config = {
        'enable_auto_block': ENABLE_AUTO_BLOCK,
        'enable_telegram': ENABLE_TELEGRAM,
        'telegram_bot_token': TELEGRAM_BOT_TOKEN,
        'telegram_chat_id': TELEGRAM_CHAT_ID,
        'min_severity_for_block': MIN_SEVERITY_FOR_BLOCK,
        'min_severity_for_notify': MIN_SEVERITY_FOR_NOTIFY,
        'auto_execute': execute,
    }
    
    # Process anomalies
    action_manager = ActionManager(action_config)
    result = action_manager.process_anomalies(anomalies_df, execute=execute)
    
    # Save actions
    if len(result['actions']) > 0:
        action_manager.save_actions(result['actions'], ACTIONS_CSV_PATH)
    
    # Save results nếu đã execute
    if len(result['results']) > 0:
        action_manager.save_results(result['results'], ACTION_RESULTS_CSV_PATH)
    
    # Print summary
    summary = result['summary']
    print(f"\n  Action Summary:")
    print(f"  Total anomalies: {summary['total_anomalies']}")
    print(f"  Total actions generated: {summary['total_actions']}")
    print(f"  Actions by type:")
    for action_type, count in summary['actions_by_type'].items():
        print(f"    {action_type}: {count}")
    if summary['executed']:
        print(f"  Execution: {summary['success_count']} success, {summary['fail_count']} failed")
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
    print("  10. Generate synthetic data")
    print("  11. Run tests")
    print("  12. Check threat intelligence")
    print("  13. Generate actions from anomalies")
    print("  14. Transfer Learning (bootstrap model)")
    print("  15. Feedback Loop (Detect → Analyze → Tune → Retrain → Test)")
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
            "detect", "classify", "realtime", "evaluate", "llm", "generate-data",
            "test", "threat-intel", "generate-actions",
            "transfer-learning", "feedback-loop"
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
    parser.add_argument(
        "--num-events",
        type=int,
        default=5000,
        help="Number of events to generate (for generate-data command)"
    )
    parser.add_argument(
        "--benign-ratio",
        type=float,
        default=0.7,
        help="Ratio of benign events 0.0-1.0 (for generate-data command)"
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="Number of days to span (for generate-data command)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path (for generate-data command)"
    )
    parser.add_argument(
        "--csv-output",
        type=str,
        default=None,
        help="Output CSV file path (for generate-data command, auto-generated if not specified)"
    )
    parser.add_argument(
        "--test-module",
        type=str,
        default=None,
        help="Specific test module to run (for test command)"
    )
    parser.add_argument(
        "--ip",
        type=str,
        default=None,
        help="IP address to check (for threat-intel command)"
    )
    parser.add_argument(
        "--hash",
        type=str,
        default=None,
        help="File hash to check (for threat-intel command)"
    )
    parser.add_argument(
        "--anomalies-csv",
        type=str,
        default=None,
        help="Anomalies CSV file path (for generate-actions command)"
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Execute actions immediately (for generate-actions command)"
    )
    args = parser.parse_args()
    
    # Nếu có --menu hoặc không có command, hiển thị menu
    if args.menu or not args.command:
        while True:
            show_menu()
            try:
                choice = input("\nNhập lựa chọn (0-15): ").strip()
                
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
                elif choice == "10":
                    generate_synthetic_data(
                        num_events=args.num_events,
                        benign_ratio=args.benign_ratio,
                        days=args.days,
                        output=args.output,
                        csv_output=args.csv_output
                    )
                elif choice == "11":
                    run_tests(test_module=args.test_module)
                elif choice == "12":
                    check_threat_intelligence(ip=args.ip, file_hash=args.hash)
                elif choice == "13":
                    generate_actions(anomalies_csv=args.anomalies_csv, execute=args.execute)
                elif choice == "14":
                    run_transfer_learning(
                        source_model=args.source_model,
                        contamination=args.contamination,
                        use_ensemble=args.ensemble
                    )
                elif choice == "15":
                    run_feedback_loop(
                        iterations=args.iterations,
                        detect_only=args.detect_only,
                        retrain=not args.no_retrain,
                        run_tests=not args.no_tests
                    )
                else:
                    print("Lựa chọn không hợp lệ! Vui lòng chọn từ 0-15.")
                
                if choice != "0":
                    input("\nNhấn Enter để tiếp tục...")
                    
            except KeyboardInterrupt:
                print("\n\nTạm biệt!")
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
        elif args.command == "generate-data":
            generate_synthetic_data(
                num_events=args.num_events,
                benign_ratio=args.benign_ratio,
                days=args.days,
                output=args.output,
                csv_output=args.csv_output
            )
        elif args.command == "test":
            run_tests(test_module=args.test_module)
        elif args.command == "threat-intel":
            check_threat_intelligence(ip=args.ip, file_hash=args.hash)
        elif args.command == "generate-actions":
            generate_actions(anomalies_csv=args.anomalies_csv, execute=args.execute)
        elif args.command == "transfer-learning":
            run_transfer_learning(
                source_model=args.source_model,
                contamination=args.contamination,
                use_ensemble=args.ensemble
            )
        elif args.command == "feedback-loop":
            run_feedback_loop(
                iterations=args.iterations,
                detect_only=args.detect_only,
                retrain=not args.no_retrain,
                run_tests=not args.no_tests
            )

if __name__ == "__main__":
    main()

