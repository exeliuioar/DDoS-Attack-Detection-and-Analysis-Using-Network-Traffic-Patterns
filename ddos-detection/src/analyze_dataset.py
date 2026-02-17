#!/usr/bin/env python3
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import argparse
import os

def analyze_dataset(input_file, output_dir='analysis_results'):
    """Comprehensive dataset analysis"""
    print(f"Analyzing {input_file}...")
    
    os.makedirs(output_dir, exist_ok=True)
    
    df = pd.read_csv(input_file)
    print(f"Dataset shape: {df.shape}")
    
    print("\n" + "="*60)
    print("BASIC STATISTICS")
    print("="*60)
    print(df.describe())
    
    if 'is_attack' in df.columns:
        print("\n" + "="*60)
        print("CLASS DISTRIBUTION")
        print("="*60)
        class_dist = df['is_attack'].value_counts()
        print(class_dist)
        
        plt.figure(figsize=(8, 6))
        class_dist.plot(kind='bar')
        plt.title('Class Distribution')
        plt.xlabel('Class (0=Benign, 1=Attack)')
        plt.ylabel('Count')
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'class_distribution.png'))
        print(f"Saved: {output_dir}/class_distribution.png")
        plt.close()
    
    print("\n" + "="*60)
    print("ANALYSIS COMPLETE")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description='Analyze dataset')
    parser.add_argument('--input', required=True, help='Input CSV file')
    parser.add_argument('--output', default='analysis_results', help='Output directory')
    
    args = parser.parse_args()
    analyze_dataset(args.input, args.output)

if __name__ == '__main__':
    main()
