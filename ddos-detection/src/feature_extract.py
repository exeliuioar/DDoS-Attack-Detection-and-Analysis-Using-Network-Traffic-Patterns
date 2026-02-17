import pandas as pd
import numpy as np
from scapy.all import *
from collections import defaultdict
import time

class FeatureExtractor:
    def __init__(self, window_size=60):
        """
        Initialize feature extractor
        window_size: Time window in seconds for flow analysis
        """
        self.window_size = window_size
        self.flows = defaultdict(list)
        self.start_time = time.time()
        
    def extract_packet_features(self, packet):
        """Extract features from a single packet"""
        features = {}
        
        if IP in packet:
            features['src_ip'] = packet[IP].src
            features['dst_ip'] = packet[IP].dst
            features['ttl'] = packet[IP].ttl
            features['packet_size'] = len(packet)
            features['protocol'] = packet[IP].proto
            
        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = packet[TCP].flags
            features['protocol_type'] = 'TCP'
            
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['protocol_type'] = 'UDP'
            
        elif ICMP in packet:
            features['protocol_type'] = 'ICMP'
            features['src_port'] = 0
            features['dst_port'] = 0
            
        features['timestamp'] = time.time()
        
        return features
    
    def extract_flow_features(self, packets_df):
        """Extract flow-level features from packet dataframe"""
        if len(packets_df) == 0:
            return {}
            
        flow_features = {}
        
        # Time-based features
        duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
        flow_features['duration'] = duration if duration > 0 else 0.001
        
        # Rate features
        flow_features['packet_rate'] = len(packets_df) / flow_features['duration']
        flow_features['byte_rate'] = packets_df['packet_size'].sum() / flow_features['duration']
        
        # Inter-arrival time
        if len(packets_df) > 1:
            timestamps = packets_df['timestamp'].sort_values()
            iat = timestamps.diff().dropna()
            flow_features['iat_mean'] = iat.mean()
            flow_features['iat_std'] = iat.std()
        else:
            flow_features['iat_mean'] = 0
            flow_features['iat_std'] = 0
            
        # Protocol distribution
        protocol_counts = packets_df['protocol_type'].value_counts()
        total = len(packets_df)
        flow_features['tcp_ratio'] = protocol_counts.get('TCP', 0) / total
        flow_features['udp_ratio'] = protocol_counts.get('UDP', 0) / total
        flow_features['icmp_ratio'] = protocol_counts.get('ICMP', 0) / total
        
        # Unique sources/destinations
        flow_features['unique_src_ips'] = packets_df['src_ip'].nunique()
        flow_features['unique_dst_ips'] = packets_df['dst_ip'].nunique()
        flow_features['unique_src_ports'] = packets_df['src_port'].nunique()
        flow_features['unique_dst_ports'] = packets_df['dst_port'].nunique()
        
        # Packet size statistics
        flow_features['avg_packet_size'] = packets_df['packet_size'].mean()
        flow_features['std_packet_size'] = packets_df['packet_size'].std()
        
        return flow_features

def extract_from_pcap(pcap_file):
    """Extract features from PCAP file"""
    extractor = FeatureExtractor()
    packets_list = []
    
    print(f"Reading packets from {pcap_file}...")
    packets = rdpcap(pcap_file)
    
    for packet in packets:
        if IP in packet:
            features = extractor.extract_packet_features(packet)
            packets_list.append(features)
    
    packets_df = pd.DataFrame(packets_list)
    flow_features = extractor.extract_flow_features(packets_df)
    
    return packets_df, flow_features
