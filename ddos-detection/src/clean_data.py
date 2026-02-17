#!/usr/bin/env python3
import pandas as pd
import numpy as np
import argparse
from sklearn.preprocessing import StandardScaler

def clean_data(input_file, output_file):
    print(f"Loading data from {input_file}...")
    df = pd.read_csv(input_file)
    
    print(f"Initial shape: {df.shape}")
    
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(df.median(numeric_only=True))
    
    constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
    df = df.drop(columns=constant_cols)
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    label_cols = ['Label', 'is_attack', 'label', 'set', 'difficulty']
    numeric_cols = [col for col in numeric_cols if col not in label_cols]
    
    if len(numeric_cols) > 0:
        scaler = StandardScaler()
        df[numeric_cols] = scaler.fit_transform(df[numeric_cols])
    
    print(f"Final shape: {df.shape}")
    print(f"Saving to {output_file}...")
    df.to_csv(output_file, index=False)
    print("Cleaning complete!")
    
    return df

def main():
    parser = argparse.ArgumentParser(description='Clean and normalize data')
    parser.add_argument('--input', required=True, help='Input CSV file')
    parser.add_argument('--output', required=True, help='Output CSV file')
    
    args = parser.parse_args()
    clean_data(args.input, args.output)

if __name__ == '__main__':
    main()
