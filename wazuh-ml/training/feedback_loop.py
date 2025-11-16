"""
Feedback Loop Module
Chu trình hoàn chỉnh: Detect → Analyze → Tune → Retrain → Test
"""

import os
import pandas as pd
import numpy as np
import joblib
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
import json

from core.config import (
    CSV_PATH, MODEL_PATH, CLASSIFIER_MODEL_PATH, ANOMALIES_CSV_PATH,
    ANALYZED_CSV_PATH, ACTIONS_CSV_PATH, ACTION_RESULTS_CSV_PATH
)
from detection.detect_anomaly import detect
from training.auto_retrain import auto_retrain
from tests.run_tests import run_all_tests
from utils.common import print_header, print_section, safe_load_csv, ensure_dataframe, safe_load_joblib


class PerformanceAnalyzer:
    """
    Phân tích performance của model và phát hiện vấn đề
    """
    
    def __init__(self):
        self.analysis_results = {}
    
    def analyze_detection_results(
        self,
        anomalies_df: pd.DataFrame,
        actions_df: Optional[pd.DataFrame] = None,
        action_results_df: Optional[pd.DataFrame] = None
    ) -> Dict:
        """
        Phân tích kết quả detection để tìm vấn đề
        
        Args:
            anomalies_df: DataFrame với detected anomalies
            actions_df: DataFrame với generated actions
            action_results_df: DataFrame với action execution results
            
        Returns:
            Dictionary với analysis results
        """
        print_header("PERFORMANCE ANALYSIS")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'total_anomalies': len(anomalies_df),
            'issues': [],
            'recommendations': [],
            'metrics': {}
        }
        
        # 1. Phân tích false positives (dựa trên attack types)
        if 'predicted_attack_type' in anomalies_df.columns:
            attack_types = anomalies_df['predicted_attack_type'].value_counts()
            benign_count = attack_types.get('benign', 0)
            
            if benign_count > 0:
                benign_ratio = benign_count / len(anomalies_df)
                analysis['metrics']['benign_anomalies_ratio'] = benign_ratio
                
                if benign_ratio > 0.3:  # >30% là benign
                    analysis['issues'].append({
                        'type': 'high_false_positives',
                        'severity': 'medium',
                        'description': f'{benign_ratio:.1%} of anomalies are benign (potential false positives)',
                        'count': benign_count
                    })
                    analysis['recommendations'].append(
                        'Consider increasing anomaly threshold or tuning model parameters'
                    )
        
        # 2. Phân tích severity distribution
        if 'severity' in anomalies_df.columns or 'rule_level' in anomalies_df.columns:
            if 'rule_level' in anomalies_df.columns:
                rule_levels = anomalies_df['rule_level'].value_counts()
                low_severity = (anomalies_df['rule_level'] < 7).sum()
                high_severity = (anomalies_df['rule_level'] >= 12).sum()
                
                analysis['metrics']['low_severity_ratio'] = low_severity / len(anomalies_df)
                analysis['metrics']['high_severity_ratio'] = high_severity / len(anomalies_df)
                
                if low_severity / len(anomalies_df) > 0.5:
                    analysis['issues'].append({
                        'type': 'too_many_low_severity',
                        'severity': 'low',
                        'description': f'{low_severity} low severity anomalies detected',
                        'count': low_severity
                    })
        
        # 3. Phân tích action execution results
        if action_results_df is not None and len(action_results_df) > 0:
            failed_actions = action_results_df[action_results_df.get('success', pd.Series([True]*len(action_results_df))) == False]
            if len(failed_actions) > 0:
                failure_rate = len(failed_actions) / len(action_results_df)
                analysis['issues'].append({
                    'type': 'action_execution_failures',
                    'severity': 'high',
                    'description': f'{len(failed_actions)} actions failed to execute ({failure_rate:.1%})',
                    'count': len(failed_actions)
                })
                analysis['recommendations'].append(
                    'Check pfSense configuration and network connectivity'
                )
        
        # 4. Phân tích model performance metrics
        bundle = safe_load_joblib(MODEL_PATH)
        if bundle:
            metrics = bundle.get('metrics', {})
            if metrics:
                analysis['metrics']['model_metrics'] = metrics
                
                # Check anomaly rate
                anomaly_rate = metrics.get('anomaly_ratio', 0)
                if anomaly_rate > 0.15:  # >15% anomalies
                    analysis['issues'].append({
                        'type': 'high_anomaly_rate',
                        'severity': 'medium',
                        'description': f'Anomaly rate is {anomaly_rate:.1%} (may indicate too sensitive)',
                        'value': anomaly_rate
                    })
                elif anomaly_rate < 0.01:  # <1% anomalies
                    analysis['issues'].append({
                        'type': 'low_anomaly_rate',
                        'severity': 'medium',
                        'description': f'Anomaly rate is {anomaly_rate:.1%} (may miss real threats)',
                        'value': anomaly_rate
                    })
        
        # 5. Phân tích feature importance (nếu có)
        if 'anomaly_score' in anomalies_df.columns:
            score_stats = {
                'mean': anomalies_df['anomaly_score'].mean(),
                'std': anomalies_df['anomaly_score'].std(),
                'min': anomalies_df['anomaly_score'].min(),
                'max': anomalies_df['anomaly_score'].max()
            }
            analysis['metrics']['score_statistics'] = score_stats
        
        self.analysis_results = analysis
        
        # Print summary
        print(f"\nAnalysis Summary:")
        print(f"   Total anomalies: {analysis['total_anomalies']}")
        print(f"   Issues found: {len(analysis['issues'])}")
        print(f"   Recommendations: {len(analysis['recommendations'])}")
        
        if analysis['issues']:
            print(f"\nIssues:")
            for issue in analysis['issues']:
                print(f"   [{issue['severity'].upper()}] {issue['type']}: {issue['description']}")
        
        if analysis['recommendations']:
            print(f"\nRecommendations:")
            for i, rec in enumerate(analysis['recommendations'], 1):
                print(f"   {i}. {rec}")
        
        return analysis
    
    def save_analysis(self, output_path: str = "data/performance_analysis.json"):
        """
        Save analysis results
        
        Args:
            output_path: Path để save analysis
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)
        print(f"\nAnalysis saved to: {output_path}")


class ModelTuner:
    """
    Tự động điều chỉnh model parameters dựa trên feedback
    """
    
    def __init__(self):
        self.tuning_history = []
    
    def tune_parameters(
        self,
        analysis_results: Dict,
        current_params: Optional[Dict] = None
    ) -> Dict:
        """
        Điều chỉnh parameters dựa trên analysis results
        
        Args:
            analysis_results: Results từ PerformanceAnalyzer
            current_params: Current model parameters
            
        Returns:
            Recommended parameters
        """
        print_header("PARAMETER TUNING")
        
        recommended_params = current_params.copy() if current_params else {}
        
        # Tune contamination dựa trên anomaly rate
        if 'model_metrics' in analysis_results.get('metrics', {}):
            metrics = analysis_results['metrics']['model_metrics']
            anomaly_rate = metrics.get('anomaly_ratio', 0.05)
            
            # Nếu anomaly rate quá cao, giảm contamination
            if anomaly_rate > 0.15:
                new_contamination = max(0.01, anomaly_rate * 0.7)
                recommended_params['contamination'] = new_contamination
                print(f"Reducing contamination: {anomaly_rate:.3f} → {new_contamination:.3f}")
            # Nếu quá thấp, tăng contamination
            elif anomaly_rate < 0.01:
                new_contamination = min(0.10, anomaly_rate * 2)
                recommended_params['contamination'] = new_contamination
                print(f"Increasing contamination: {anomaly_rate:.3f} → {new_contamination:.3f}")
        
        # Tune voting threshold dựa trên false positives
        issues = analysis_results.get('issues', [])
        for issue in issues:
            if issue['type'] == 'high_false_positives':
                if 'voting_threshold' not in recommended_params:
                    recommended_params['voting_threshold'] = 3  # Stricter
                    print(f"Increasing voting threshold: 2 → 3 (stricter)")
        
        # Tune threshold dựa trên severity distribution
        for issue in issues:
            if issue['type'] == 'too_many_low_severity':
                if 'min_severity_threshold' not in recommended_params:
                    recommended_params['min_severity_threshold'] = 7
                    print(f"Setting min severity threshold: 7")
        
        self.tuning_history.append({
            'timestamp': datetime.now().isoformat(),
            'analysis': analysis_results,
            'recommended_params': recommended_params
        })
        
        return recommended_params
    
    def save_tuning_history(self, output_path: str = "data/tuning_history.json"):
        """
        Save tuning history
        
        Args:
            output_path: Path để save history
        """
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(self.tuning_history, f, indent=2, default=str)


class FeedbackLoop:
    """
    Feedback Loop hoàn chỉnh: Detect → Analyze → Tune → Retrain → Test
    """
    
    def __init__(self):
        self.analyzer = PerformanceAnalyzer()
        self.tuner = ModelTuner()
        self.iteration = 0
    
    def run_full_cycle(
        self,
        detect_only: bool = False,
        retrain: bool = True,
        run_tests: bool = True,
        save_results: bool = True
    ) -> Dict:
        """
        Chạy full feedback loop cycle
        
        Args:
            detect_only: Chỉ detect, không retrain
            retrain: Có retrain model không
            run_tests: Có chạy tests không
            save_results: Có save results không
            
        Returns:
            Dictionary với cycle results
        """
        self.iteration += 1
        print_header(f"FEEDBACK LOOP - ITERATION {self.iteration}")
        
        cycle_results = {
            'iteration': self.iteration,
            'timestamp': datetime.now().isoformat(),
            'steps': {}
        }
        
        # Step 1: Detect
        print_section("STEP 1: DETECT")
        try:
            anomalies = detect()
            anomalies_df = ensure_dataframe(anomalies)
            
            if len(anomalies_df) > 0:
                print(f"Detected {len(anomalies_df)} anomalies")
                cycle_results['steps']['detect'] = {
                    'status': 'success',
                    'anomalies_count': len(anomalies_df)
                }
            else:
                print("No anomalies detected")
                cycle_results['steps']['detect'] = {
                    'status': 'no_anomalies',
                    'anomalies_count': 0
                }
        except Exception as e:
            print(f"Detection failed: {e}")
            cycle_results['steps']['detect'] = {
                'status': 'failed',
                'error': str(e)
            }
            return cycle_results
        
        # Step 2: Analyze
        print_section("STEP 2: ANALYZE")
        try:
            # Load actions và results nếu có
            actions_df = safe_load_csv(ACTIONS_CSV_PATH)
            action_results_df = safe_load_csv(ACTION_RESULTS_CSV_PATH)
            
            analysis = self.analyzer.analyze_detection_results(
                anomalies_df=anomalies_df,
                actions_df=actions_df,
                action_results_df=action_results_df
            )
            
            cycle_results['steps']['analyze'] = {
                'status': 'success',
                'issues_count': len(analysis['issues']),
                'recommendations_count': len(analysis['recommendations'])
            }
            
            if save_results:
                self.analyzer.save_analysis()
        except Exception as e:
            print(f"Analysis failed: {e}")
            cycle_results['steps']['analyze'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        # Step 3: Tune
        print_section("STEP 3: TUNE")
        try:
            if analysis is None:
                print("  No analysis results, skipping tuning")
                cycle_results['steps']['tune'] = {
                    'status': 'skipped',
                    'reason': 'no_analysis'
                }
            else:
                # Load current model params
                current_params = {}
                bundle = safe_load_joblib(MODEL_PATH)
                if bundle:
                    current_params = bundle.get('best_params', {})
                
                recommended_params = self.tuner.tune_parameters(
                    analysis_results=analysis,
                    current_params=current_params
                )
                
                cycle_results['steps']['tune'] = {
                    'status': 'success',
                    'recommended_params': recommended_params
                }
                
                if save_results:
                    self.tuner.save_tuning_history()
        except Exception as e:
            print(f"Tuning failed: {e}")
            cycle_results['steps']['tune'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        # Step 4: Retrain (nếu cần)
        if retrain and not detect_only:
            print_section("STEP 4: RETRAIN")
            try:
                # Check if retrain is needed
                from training.auto_retrain import should_retrain
                should_train, reason = should_retrain(force=False, max_age_days=7)
                
                if should_train:
                    print(f"   Reason: {reason}")
                    success = auto_retrain(
                        fetch_new_data=True,
                        force=False,
                        enable_tuning=True
                    )
                    cycle_results['steps']['retrain'] = {
                        'status': 'success' if success else 'skipped',
                        'reason': reason
                    }
                else:
                    print(f"{reason}")
                    cycle_results['steps']['retrain'] = {
                        'status': 'skipped',
                        'reason': reason
                    }
            except Exception as e:
                print(f"Retrain failed: {e}")
                cycle_results['steps']['retrain'] = {
                    'status': 'failed',
                    'error': str(e)
                }
        else:
            cycle_results['steps']['retrain'] = {
                'status': 'skipped',
                'reason': 'retrain disabled or detect_only mode'
            }
        
        # Step 5: Test
        if run_tests:
            print_section("STEP 5: TEST")
            try:
                test_success = run_all_tests()
                cycle_results['steps']['test'] = {
                    'status': 'success' if test_success else 'failed',
                    'all_passed': test_success
                }
            except Exception as e:
                print(f"Tests failed: {e}")
                cycle_results['steps']['test'] = {
                    'status': 'failed',
                    'error': str(e)
                }
        else:
            cycle_results['steps']['test'] = {
                'status': 'skipped',
                'reason': 'tests disabled'
            }
        
        # Summary
        print_header("FEEDBACK LOOP SUMMARY")
        print(f"Iteration: {self.iteration}")
        print(f"Timestamp: {cycle_results['timestamp']}")
        for step, result in cycle_results['steps'].items():
            status = result.get('status', 'unknown')
            print(f"  {step.upper()}: {status}")
        
        # Save cycle results
        if save_results:
            cycle_path = f"data/feedback_loop_iteration_{self.iteration}.json"
            os.makedirs(os.path.dirname(cycle_path), exist_ok=True)
            with open(cycle_path, 'w') as f:
                json.dump(cycle_results, f, indent=2, default=str)
            print(f"\nCycle results saved to: {cycle_path}")
        
        return cycle_results


def run_feedback_loop(
    iterations: int = 1,
    detect_only: bool = False,
    retrain: bool = True,
    run_tests: bool = True
) -> List[Dict]:
    """
    Chạy feedback loop nhiều iterations
    
    Args:
        iterations: Số iterations
        detect_only: Chỉ detect, không retrain
        retrain: Có retrain không
        run_tests: Có chạy tests không
        
    Returns:
        List of cycle results
    """
    loop = FeedbackLoop()
    results = []
    
    for i in range(iterations):
        result = loop.run_full_cycle(
            detect_only=detect_only,
            retrain=retrain,
            run_tests=run_tests
        )
        results.append(result)
        
        if i < iterations - 1:
            print(f"\nWaiting before next iteration...")
            import time
            time.sleep(5)  # Wait 5 seconds between iterations
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Feedback Loop: Detect → Analyze → Tune → Retrain → Test")
    parser.add_argument("--iterations", type=int, default=1, help="Number of iterations")
    parser.add_argument("--detect-only", action="store_true", help="Only detect, don't retrain")
    parser.add_argument("--no-retrain", action="store_true", help="Don't retrain")
    parser.add_argument("--no-tests", action="store_true", help="Don't run tests")
    
    args = parser.parse_args()
    
    results = run_feedback_loop(
        iterations=args.iterations,
        detect_only=args.detect_only,
        retrain=not args.no_retrain,
        run_tests=not args.no_tests
    )
    
    print(f"\nCompleted {len(results)} feedback loop iteration(s)")

