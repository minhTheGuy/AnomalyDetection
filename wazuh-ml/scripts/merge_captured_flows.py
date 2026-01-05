#!/usr/bin/env python3
"""
merge_captured_flows.py - Merge all captured flow files and label as BENIGN

This script combines all captured network flow CSV files into a single labeled dataset
for training classification models (XGBoost).

Usage:
    python merge_captured_flows.py --output merged_benign_flows.csv
"""

import pandas as pd
import argparse
from pathlib import Path
from datetime import datetime

# Import project paths
import sys
from pathlib import Path
PROJECT_DIR = Path(__file__).parent.parent
CAPTURED_DIR = PROJECT_DIR / 'data' / 'captured' / 'flows'
LABELED_DIR = PROJECT_DIR / 'data' / 'labeled' / 'flows'

def merge_captured_flows(output_file: str = None):
    """Merge all captured flow files and label as BENIGN"""

    print("🔄 Merging captured flow files...")

    # Find all CSV files in captured flows directory
    flow_files = list(CAPTURED_DIR.glob("*.csv"))
    print(f"Found {len(flow_files)} flow files in {CAPTURED_DIR}")

    if not flow_files:
        print("❌ No flow files found!")
        return None

    # Read and combine all files
    dfs = []
    total_flows = 0

    for csv_file in sorted(flow_files):
        try:
            df = pd.read_csv(csv_file, low_memory=False)
            df.columns = df.columns.str.strip()  # Clean column names

            # Skip empty files
            if len(df) == 0:
                continue

            # Add Label column
            df['Label'] = 'BENIGN'

            dfs.append(df)
            total_flows += len(df)
            print(f"  ✓ {csv_file.name}: {len(df):,} flows")

        except Exception as e:
            print(f"  ❌ Error reading {csv_file.name}: {e}")
            continue

    if not dfs:
        print("❌ No valid flow data found!")
        return None

    # Concatenate all dataframes
    merged_df = pd.concat(dfs, ignore_index=True)

    # Remove duplicates if any
    original_count = len(merged_df)
    merged_df = merged_df.drop_duplicates()
    if len(merged_df) < original_count:
        print(f"Removed {original_count - len(merged_df)} duplicate flows")

    print(f"\n📊 Merged dataset: {len(merged_df):,} flows, {len(merged_df.columns)} columns")

    # Generate output filename if not provided
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"merged_benign_flows_{timestamp}.csv"

    # Ensure output directory exists
    output_path = LABELED_DIR / output_file
    LABELED_DIR.mkdir(parents=True, exist_ok=True)

    # Save merged dataset
    merged_df.to_csv(output_path, index=False)
    print(f"💾 Saved to: {output_path}")

    # Print summary
    print(f"\n✅ Successfully merged {len(flow_files)} files into {len(merged_df)} BENIGN flows")
    print(f"   Features: {len(merged_df.columns) - 1} (plus Label column)")

    return output_path

def main():
    parser = argparse.ArgumentParser(description='Merge captured flows and label as BENIGN')
    parser.add_argument('--output', '-o', help='Output filename (default: auto-generated)')
    parser.add_argument('--preview', action='store_true', help='Show preview of merged data')

    args = parser.parse_args()

    # Merge the files
    output_path = merge_captured_flows(args.output)

    if output_path and args.preview:
        print(f"\n🔍 Preview of {output_path.name}:")
        df = pd.read_csv(output_path, nrows=5)
        print(df.head())
        print(f"\nColumns: {list(df.columns)}")
        print(f"Label distribution: {df['Label'].value_counts().to_dict()}")

if __name__ == '__main__':
    main()