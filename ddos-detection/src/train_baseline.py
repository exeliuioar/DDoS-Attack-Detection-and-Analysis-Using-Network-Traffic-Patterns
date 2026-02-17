#!/usr/bin/env python3
import pandas as pd
import numpy as np
import argparse
from feature_extract import extract_from_pcap
from utils import save_model

def train_baseline(input_file, output_file):
    """
    Train baseline profile from normal traffic
    """
    print(f"Training baseline from {input_file}")
    
    # Extract features
    packets_df, flow_features = extract_from_pcap(input_file)
    
    # Calculate baseline statistics
    baseline = {
        # Packet rate thresholds
        'packet_rate_mean': flow_features['packet_rate'],
        'packet_rate_threshold': flow_features['packet_rate'] * 3,  # 3x normal
        
        # Byte rate thresholds
        'byte_rate_mean': flow_features['byte_rate'],
        'byte_rate_threshold': flow_features['byte_rate'] * 3,
        
        # Connection diversity
        'unique_src_ips_mean': flow_features['unique_src_ips'],
        'unique_dst_ips_mean': flow_features['unique_dst_ips'],
        
        # Protocol distribution
        'tcp_ratio_normal': flow_features['tcp_ratio'],
        'udp_ratio_normal': flow_features['udp_ratio'],
        'icmp_ratio_normal': flow_features['icmp_ratio'],
        
        # Entropy thresholds
        'entropy_threshold': 2.5,  # Low entropy threshold
    }
    
    print("\nBaseline Profile:")
    for key, value in baseline.items():
        print(f"  {key}: {value:.2f}")
    
    # Save baseline
    save_model(baseline, output_file)
    print(f"\nBaseline saved to {output_file}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train baseline from normal traffic')
    parser.add_argument('--input', required=True, help='Input PCAP file with normal traffic')
    parser.add_argument('--output', default='models/baseline.pkl', help='Output baseline file')
    
    args = parser.parse_args()
    train_baseline(args.input, args.output)
