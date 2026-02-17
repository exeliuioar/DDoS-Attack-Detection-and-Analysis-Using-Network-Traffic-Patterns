#!/usr/bin/env python3
import argparse
import pandas as pd
from scapy.all import *
from feature_extract import FeatureExtractor, extract_from_pcap
from entropy import analyze_entropy
from utils import load_model, log_alert
import time

class DDoSDetector:
    def __init__(self, baseline_file='models/baseline.pkl'):
        """Initialize DDoS detector with baseline"""
        self.baseline = load_model(baseline_file)
        self.extractor = FeatureExtractor(window_size=60)
        self.packet_buffer = []
        self.window_start = time.time()
        
    def detect_anomaly(self, flow_features, entropy_results):
        """
        Detect if current traffic is anomalous
        """
        alerts = []
        
        # Check packet rate
        if flow_features['packet_rate'] > self.baseline['packet_rate_threshold']:
            alerts.append(f"High packet rate: {flow_features['packet_rate']:.2f} pps")
        
        # Check byte rate
        if flow_features['byte_rate'] > self.baseline['byte_rate_threshold']:
            alerts.append(f"High byte rate: {flow_features['byte_rate']:.2f} Bps")
        
        # Check entropy
        if entropy_results['src_ip_entropy'] < self.baseline['entropy_threshold']:
            alerts.append(f"Low source IP entropy: {entropy_results['src_ip_entropy']:.2f}")
        
        # Check protocol anomalies
        tcp_diff = abs(flow_features['tcp_ratio'] - self.baseline['tcp_ratio_normal'])
        udp_diff = abs(flow_features['udp_ratio'] - self.baseline['udp_ratio_normal'])
        
        if udp_diff > 0.3:  # 30% deviation
            alerts.append(f"Unusual UDP ratio: {flow_features['udp_ratio']:.2f}")
        
        return len(alerts) > 0, alerts
    
    def analyze_window(self):
        """Analyze accumulated packets in current window"""
        if len(self.packet_buffer) == 0:
            return False, []
        
        # Convert to DataFrame
        packets_df = pd.DataFrame(self.packet_buffer)
        
        # Extract features
        flow_features = self.extractor.extract_flow_features(packets_df)
        
        # Calculate entropy
        entropy_results = analyze_entropy(packets_df)
        
        # Detect anomalies
        is_attack, alerts = self.detect_anomaly(flow_features, entropy_results)
        
        if is_attack:
            log_alert(f"DDoS ATTACK DETECTED: {', '.join(alerts)}")
            print("\n" + "="*60)
            print("🚨 DDoS ATTACK DETECTED 🚨")
            print("="*60)
            for alert in alerts:
                print(f"  - {alert}")
            print("="*60 + "\n")
        
        # Clear buffer for next window
        self.packet_buffer = []
        self.window_start = time.time()
        
        return is_attack, alerts
    
    def process_packet(self, packet):
        """Process individual packet"""
        if IP in packet:
            features = self.extractor.extract_packet_features(packet)
            self.packet_buffer.append(features)
            
            # Check if window elapsed
            if time.time() - self.window_start >= self.extractor.window_size:
                self.analyze_window()
    
    def detect_from_pcap(self, pcap_file):
        """Run detection on PCAP file"""
        print(f"Analyzing {pcap_file}...")
        
        packets_df, flow_features = extract_from_pcap(pcap_file)
        entropy_results = analyze_entropy(packets_df)
        
        is_attack, alerts = self.detect_anomaly(flow_features, entropy_results)
        
        print("\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)
        print(f"\nFlow Statistics:")
        for key, value in flow_features.items():
            print(f"  {key}: {value:.2f}")
        
        print(f"\nEntropy Analysis:")
        for key, value in entropy_results.items():
            if isinstance(value, bool):
                print(f"  {key}: {value}")
            else:
                print(f"  {key}: {value:.2f}")
        
        if is_attack:
            print(f"\n🚨 DDoS ATTACK DETECTED!")
            for alert in alerts:
                print(f"  - {alert}")
        else:
            print(f"\n✓ Normal traffic detected")
        
        print("="*60 + "\n")
        
        return is_attack
    
    def detect_live(self, interface='eth0'):
        """Run detection on live network interface"""
        print(f"Starting live detection on {interface}...")
        print(f"Window size: {self.extractor.window_size} seconds")
        print("Press Ctrl+C to stop\n")
        
        try:
            sniff(iface=interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            print("\nStopping detection...")
            if len(self.packet_buffer) > 0:
                self.analyze_window()

def main():
    parser = argparse.ArgumentParser(description='DDoS Attack Detector')
    parser.add_argument('--interface', help='Network interface for live capture')
    parser.add_argument('--pcap', help='PCAP file to analyze')
    parser.add_argument('--baseline', default='models/baseline.pkl', help='Baseline model file')
    parser.add_argument('--threshold', type=int, default=1000, help='Packet rate threshold')
    
    args = parser.parse_args()
    
    if not args.interface and not args.pcap:
        parser.error("Must specify either --interface or --pcap")
    
    detector = DDoSDetector(baseline_file=args.baseline)
    
    if args.pcap:
        detector.detect_from_pcap(args.pcap)
    elif args.interface:
        detector.detect_live(args.interface)

if __name__ == '__main__':
    main()
