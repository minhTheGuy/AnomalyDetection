"""
create_test_dataset.py - Create a test dataset with samples from each attack type

This script samples flows from CIC-IDS-2017 dataset to create a balanced test set
with a specified number of samples per attack type.

Usage:
    python scripts/create_test_dataset.py --samples 100
    python scripts/create_test_dataset.py --samples 50 --output data/test/test_flows.csv
"""

import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

# Paths
DATA_DIR = Path(__file__).parent.parent / 'data' / 'cicids'
OUTPUT_DIR = Path(__file__).parent.parent / 'data' / 'test'


def main():
    parser = argparse.ArgumentParser(description='Create test dataset from CIC-IDS-2017')
    parser.add_argument('--samples', type=int, default=100,
                       help='Number of samples per attack type (default: 100)')
    parser.add_argument('--output', type=Path, default=None,
                       help='Output CSV path (default: data/test/test_flows_TIMESTAMP.csv)')
    parser.add_argument('--include-benign', action='store_true',
                       help='Also include benign samples')
    args = parser.parse_args()
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print(f"Loading CIC-IDS-2017 data from: {DATA_DIR}")
    
    # Load all CSV files
    csv_files = sorted(DATA_DIR.glob('*.csv'))
    if not csv_files:
        print(f"ERROR: No CSV files found in {DATA_DIR}")
        return 1
    
    print(f"Found {len(csv_files)} CSV files")
    
    # Load and combine all data
    dfs = []
    for csv_file in csv_files:
        print(f"  Loading {csv_file.name}...")
        df = pd.read_csv(csv_file, low_memory=False)
        df.columns = df.columns.str.strip()
        dfs.append(df)
    
    data = pd.concat(dfs, ignore_index=True)
    print(f"\nTotal rows: {len(data):,}")
    
    # Get attack type distribution
    print(f"\nAttack type distribution:")
    label_counts = data['Label'].value_counts()
    for label, count in label_counts.items():
        print(f"  {label}: {count:,}")
    
    # Sample from each attack type
    samples = []
    attack_types = data['Label'].unique()
    
    print(f"\nSampling {args.samples} from each attack type...")
    
    for attack_type in sorted(attack_types):
        if attack_type.upper() == 'BENIGN' and not args.include_benign:
            continue
        
        attack_data = data[data['Label'] == attack_type]
        n_samples = min(args.samples, len(attack_data))
        
        if n_samples > 0:
            sampled = attack_data.sample(n=n_samples, random_state=42)
            samples.append(sampled)
            print(f"  {attack_type}: {n_samples} samples")
    
    if args.include_benign:
        benign_data = data[data['Label'].str.upper() == 'BENIGN']
        n_samples = min(args.samples, len(benign_data))
        if n_samples > 0:
            sampled = benign_data.sample(n=n_samples, random_state=42)
            samples.append(sampled)
            print(f"  BENIGN: {n_samples} samples")
    
    # Combine samples
    test_data = pd.concat(samples, ignore_index=True)
    
    # Shuffle the dataset
    test_data = test_data.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Create output path
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = OUTPUT_DIR / f'test_flows_{timestamp}.csv'
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Save to CSV
    test_data.to_csv(output_path, index=False)
    
    print(f"\n{'='*60}")
    print(f"Test dataset created!")
    print(f"{'='*60}")
    print(f"  Output: {output_path}")
    print(f"  Total samples: {len(test_data):,}")
    print(f"  Attack types: {len(samples)}")
    print(f"\nSample distribution:")
    for label, count in test_data['Label'].value_counts().items():
        print(f"  {label}: {count}")
    
    print(f"\nTo test detection, run:")
    print(f"  python tests/test_flows_detection.py --flows {output_path}")
    
    return 0


if __name__ == '__main__':
    exit(main())
