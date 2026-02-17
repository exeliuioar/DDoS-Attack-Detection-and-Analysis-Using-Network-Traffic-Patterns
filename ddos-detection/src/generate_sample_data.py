#!/usr/bin/env python3
"""Generate sample network traffic for testing"""

import pandas as pd
import numpy as np
from scapy.all import *
import argparse
import random

def generate_normal_traffic(num_packets=1000):
    """Generate normal network traffic"""
    packets = []
    
    # Simulate diverse source IPs
    src_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 10)]
    
    timestamp = 0.0
    
    for i in range(num_packets):
        # Random source and destination
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        
        # Random ports
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 25])
        
        # Random packet size (typical web traffic)
        packet_size = random.randint(64, 1500)
        
        # Protocol distribution (70% TCP, 20% UDP, 10% ICMP)
        proto = random.choices(['TCP', 'UDP', 'ICMP'], weights=[0.7, 0.2, 0.1])[0]
        
        packets.append({
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'packet_size': packet_size,
            'protocol_type': proto,
            'timestamp': timestamp
        })
        
        # Inter-arrival time (normal distribution around 0.01s)
        timestamp += max(0.001, np.random.normal(0.01, 0.005))
    
    return pd.DataFrame(packets)

def generate_ddos_traffic(num_packets=5000, attack_type='udp_flood'):
    """Generate DDoS attack traffic"""
    packets = []
    
    if attack_type == 'udp_flood':
        # Few source IPs (botnet)
        src_ips = [f"203.0.113.{i}" for i in range(1, 10)]
        dst_ip = "10.0.0.1"  # Target server
        dst_port = 80
        
        timestamp = 0.0
        
        for i in range(num_packets):
            src_ip = random.choice(src_ips)
            src_port = random.randint(1024, 65535)
            packet_size = random.randint(32, 128)  # Small packets
            
            packets.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'packet_size': packet_size,
                'protocol_type': 'UDP',
                'timestamp': timestamp
            })
            
            # Very short inter-arrival time (flooding)
            timestamp += max(0.0001, np.random.normal(0.001, 0.0005))
    
    elif attack_type == 'syn_flood':
        # SYN flood attack
        src_ips = [f"198.51.100.{i}" for i in range(1, 20)]
        dst_ip = "10.0.0.1"
        dst_port = 80
        
        timestamp = 0.0
        
        for i in range(num_packets):
            src_ip = random.choice(src_ips)
            src_port = random.randint(1024, 65535)
            packet_size = 60  # SYN packet size
            
            packets.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'packet_size': packet_size,
                'protocol_type': 'TCP',
                'timestamp': timestamp
            })
            
            timestamp += max(0.0001, np.random.normal(0.002, 0.001))
    
    return pd.DataFrame(packets)

def save_to_pcap(packets_df, output_file):
    """Save packets to PCAP file"""
    packet_list = []
    
    for _, row in packets_df.iterrows():
        if row['protocol_type'] == 'TCP':
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / \
                  TCP(sport=row['src_port'], dport=row['dst_port']) / \
                  Raw(load='X' * max(0, row['packet_size'] - 40))
        elif row['protocol_type'] == 'UDP':
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / \
                  UDP(sport=row['src_port'], dport=row['dst_port']) / \
                  Raw(load='X' * max(0, row['packet_size'] - 28))
        else:  # ICMP
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / ICMP()
        
        packet_list.append(pkt)
    
    wrpcap(output_file, packet_list)
    print(f"Saved {len(packet_list)} packets to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate sample network traffic')
    parser.add_argument('--type', choices=['normal', 'udp_flood', 'syn_flood'], required=True)
    parser.add_argument('--packets', type=int, default=1000, help='Number of packets')
    parser.add_argument('--output', required=True, help='Output PCAP file')
    parser.add_argument('--csv', help='Also save as CSV')
    
    args = parser.parse_args()
    
    print(f"Generating {args.type} traffic with {args.packets} packets...")
    
    if args.type == 'normal':
        df = generate_normal_traffic(args.packets)
    else:
        df = generate_ddos_traffic(args.packets, args.type)
    
    # Save to PCAP
    save_to_pcap(df, args.output)
    
    # Optionally save to CSV
    if args.csv:
        df.to_csv(args.csv, index=False)
        print(f"Saved CSV to {args.csv}")
    
    # Print statistics
    print(f"\nTraffic Statistics:")
    print(f"  Total packets: {len(df)}")
    print(f"  Unique source IPs: {df['src_ip'].nunique()}")
    print(f"  Unique destination IPs: {df['dst_ip'].nunique()}")
    print(f"  Duration: {df['timestamp'].max():.2f} seconds")
    print(f"  Packet rate: {len(df)/df['timestamp'].max():.2f} pps")
    print(f"  Protocol distribution:")
    print(df['protocol_type'].value_counts())

if __name__ == '__main__':
    main()
