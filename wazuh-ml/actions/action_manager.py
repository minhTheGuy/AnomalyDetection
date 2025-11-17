"""
Action Manager - Quản lý và điều phối actions
"""
import pandas as pd
from typing import Dict, List, Optional

from actions.action_generator import ActionGenerator
from actions.action_executor import ActionExecutor
from utils.common import safe_save_csv, print_header


class ActionManager:
    """Manager cho action generation và execution"""
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize action manager
        
        Args:
            config: Configuration dict
        """
        self.config = config or {}
        self.generator = ActionGenerator(config)
        self.executor = ActionExecutor(config)
        self.auto_execute = self.config.get('auto_execute', False)
    
    def process_anomalies(self, anomalies_df: pd.DataFrame, 
                         execute: Optional[bool] = None) -> Dict:
        """Generate (and optionally execute) actions for detected anomalies."""
        if anomalies_df.empty:
            return self._package_result(pd.DataFrame(), pd.DataFrame(), anomalies_df, executed=False)
        
        print_header("ACTION GENERATION", width=60)
        print(f"Generating actions for {len(anomalies_df)} anomalies...")
        actions_df = self.generator.generate_actions_batch(anomalies_df)
        self._print_action_breakdown(actions_df)
        
        should_execute = execute if execute is not None else self.auto_execute
        results_df = self._execute_if_needed(actions_df, should_execute)
        
        return self._package_result(actions_df, results_df, anomalies_df, should_execute)
    
    @staticmethod
    def _print_action_breakdown(actions_df: pd.DataFrame):
        print(f"  Generated {len(actions_df)} actions")
        if actions_df.empty:
            return
        print("\nAction breakdown:")
        for action_type, count in actions_df['action_type'].value_counts().items():
            print(f"  {action_type}: {count}")
    
    def _execute_if_needed(self, actions_df: pd.DataFrame, should_execute: bool) -> pd.DataFrame:
        if not should_execute or actions_df.empty:
            print("\nActions generated but not executed (enable auto_execute to run them)")
            return pd.DataFrame()
        
        print(f"\nExecuting {len(actions_df)} actions...")
        results_df = self.executor.execute_actions_batch(actions_df)
        success_count = results_df['success'].sum()
        fail_count = (~results_df['success']).sum()
        print(f"  Success: {success_count}")
        print(f"  Failed: {fail_count}")
        return results_df
    
    @staticmethod
    def _package_result(actions_df: pd.DataFrame, results_df: pd.DataFrame,
                        anomalies_df: pd.DataFrame, executed: bool) -> Dict:
        summary = {
            'total_anomalies': len(anomalies_df),
            'total_actions': len(actions_df),
            'actions_by_type': actions_df['action_type'].value_counts().to_dict() if not actions_df.empty else {},
            'executed': executed,
            'success_count': int(results_df['success'].sum()) if not results_df.empty else 0,
            'fail_count': int((~results_df['success']).sum()) if not results_df.empty else 0,
        }
        return {'actions': actions_df, 'results': results_df, 'summary': summary}
    
    def save_actions(self, actions_df: pd.DataFrame, output_path: str):
        """Save actions to CSV"""
        if safe_save_csv(actions_df, output_path):
            print(f"Actions saved to {output_path}")
    
    def save_results(self, results_df: pd.DataFrame, output_path: str):
        """Save execution results to CSV"""
        if safe_save_csv(results_df, output_path):
            print(f"Execution results saved to {output_path}")

