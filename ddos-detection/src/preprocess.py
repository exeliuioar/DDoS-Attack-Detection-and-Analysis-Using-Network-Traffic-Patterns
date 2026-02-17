#!/usr/bin/env python3
import pandas as pd
import numpy as np
import argparse
import os
from tqdm import tqdm

class DataPreprocessor:
    def __init__(self, dataset_type='cicids2017'):
        self.dataset_type = dataset_type
        
    def preprocess_cicids2017(self, input_dir, output_file):
        """Preprocess CICIDS2017 dataset"""
        print("Preprocessing CICIDS2017 dataset...")
        
        # Find all CSV files
        csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]
        print(f"Found {len(csv_files)} CSV files")
        
        dataframes = []
        for csv_file in tqdm(csv_files, desc="Loading files"):
            filepath = os.path.join(input_dir, csv_file)
            try:
                df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
                dataframes.append(df)
            except Exception as e:
                print(f"Error loading {csv_file}: {e}")
        
        # Concatenate all dataframes
        print("Concatenating dataframes...")
        df = pd.concat(dataframes, ignore_index=True)
        print(f"Total records: {len(df)}")
        
        # Clean column names
        df.columns = df.columns.str.strip()
        
        # Handle missing values
        print("Handling missing values...")
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Remove duplicates
        print("Removing duplicates...")
        df = df.drop_duplicates()
        print(f"Records after deduplication: {len(df)}")
        
        # Standardize label column
        if 'Label' in df.columns:
            df['Label'] = df['Label'].str.strip()
            # Binary classification: BENIGN vs ATTACK
            df['is_attack'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)
        
        # Save preprocessed data
        print(f"Saving to {output_file}...")
        df.to_csv(output_file, index=False)
        print("Preprocessing complete!")
        
        # Print statistics
        print("\nDataset Statistics:")
        print(f"  Total samples: {len(df)}")
        if 'is_attack' in df.columns:
            print(f"  Benign samples: {(df['is_attack']==0).sum()}")
            print(f"  Attack samples: {(df['is_attack']==1).sum()}")
            print(f"  Attack types: {df['Label'].nunique()}")
        
        return df
    
    def preprocess_nslkdd(self, input_dir, output_file):
        """Preprocess NSL-KDD dataset"""
        print("Preprocessing NSL-KDD dataset...")
        
        # NSL-KDD column names
        columns = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
        ]
        
        # Load training and test sets
        train_file = os.path.join(input_dir, 'KDDTrain+.txt')
        test_file = os.path.join(input_dir, 'KDDTest+.txt')
        
        dataframes = []
        
        if os.path.exists(train_file):
            print("Loading training set...")
            df_train = pd.read_csv(train_file, names=columns, header=None)
            df_train['set'] = 'train'
            dataframes.append(df_train)
        
        if os.path.exists(test_file):
            print("Loading test set...")
            df_test = pd.read_csv(test_file, names=columns, header=None)
            df_test['set'] = 'test'
            dataframes.append(df_test)
        
        df = pd.concat(dataframes, ignore_index=True)
        print(f"Total records: {len(df)}")
        
        # Clean labels
        df['label'] = df['label'].str.strip()
        
        # Create binary classification
        df['is_attack'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
        
        # One-hot encode categorical features
        categorical_features = ['protocol_type', 'service', 'flag']
        df = pd.get_dummies(df, columns=categorical_features, prefix=categorical_features)
        
        # Save preprocessed data
        print(f"Saving to {output_file}...")
        df.to_csv(output_file, index=False)
        print("Preprocessing complete!")
        
        # Print statistics
        print("\nDataset Statistics:")
        print(f"  Total samples: {len(df)}")
        print(f"  Normal samples: {(df['is_attack']==0).sum()}")
        print(f"  Attack samples: {(df['is_attack']==1).sum()}")
        print(f"  Attack types: {df['label'].nunique()}")
        
        return df

def main():
    parser = argparse.ArgumentParser(description='Preprocess datasets')
    parser.add_argument('--dataset', required=True, choices=['cicids2017', 'nsl-kdd'])
    parser.add_argument('--input', required=True, help='Input directory')
    parser.add_argument('--output', required=True, help='Output file path')
    
    args = parser.parse_args()
    
    preprocessor = DataPreprocessor(args.dataset)
    
    if args.dataset == 'cicids2017':
        preprocessor.preprocess_cicids2017(args.input, args.output)
    elif args.dataset == 'nsl-kdd':
        preprocessor.preprocess_nslkdd(args.input, args.output)

if __name__ == '__main__':
    main()
