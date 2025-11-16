"""
Action Manager - Quản lý và điều phối actions
"""
import os
import pandas as pd
from typing import Dict, List, Optional

from actions.action_generator import ActionGenerator
from actions.action_executor import ActionExecutor


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
        """
        Process anomalies: generate và execute actions
        
        Args:
            anomalies_df: DataFrame chứa anomalies
            execute: Có thực thi actions không (None = dùng config)
            
        Returns:
            Dict với:
            - actions: DataFrame các actions được generate
            - results: DataFrame kết quả execution (nếu execute=True)
            - summary: Dict summary statistics
        """
        if len(anomalies_df) == 0:
            return {
                'actions': pd.DataFrame(),
                'results': pd.DataFrame(),
                'summary': {'total_anomalies': 0, 'total_actions': 0}
            }
        
        # Generate actions
        print(f"\nGenerating actions for {len(anomalies_df)} anomalies...")
        actions_df = self.generator.generate_actions_batch(anomalies_df)
        print(f"  Generated {len(actions_df)} actions")
        
        # Count actions by type
        action_counts = actions_df['action_type'].value_counts()
        print(f"\nAction breakdown:")
        for action_type, count in action_counts.items():
            print(f"  {action_type}: {count}")
        
        results_df = pd.DataFrame()
        
        # Execute actions nếu được yêu cầu
        should_execute = execute if execute is not None else self.auto_execute
        if should_execute:
            print(f"\nExecuting {len(actions_df)} actions...")
            results_df = self.executor.execute_actions_batch(actions_df)
            
            # Summary execution results
            success_count = results_df['success'].sum()
            fail_count = (~results_df['success']).sum()
            print(f"  Success: {success_count}")
            print(f"  Failed: {fail_count}")
        else:
            print("\nActions generated but not executed (use --execute flag to execute)")
        
        # Summary
        summary = {
            'total_anomalies': len(anomalies_df),
            'total_actions': len(actions_df),
            'actions_by_type': action_counts.to_dict(),
            'executed': should_execute,
            'success_count': len(results_df[results_df['success']]) if len(results_df) > 0 else 0,
            'fail_count': len(results_df[~results_df['success']]) if len(results_df) > 0 else 0,
        }
        
        return {
            'actions': actions_df,
            'results': results_df,
            'summary': summary,
        }
    
    def save_actions(self, actions_df: pd.DataFrame, output_path: str):
        """Save actions to CSV"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        actions_df.to_csv(output_path, index=False)
        print(f"Actions saved to {output_path}")
    
    def save_results(self, results_df: pd.DataFrame, output_path: str):
        """Save execution results to CSV"""
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        results_df.to_csv(output_path, index=False)
        print(f"Execution results saved to {output_path}")

