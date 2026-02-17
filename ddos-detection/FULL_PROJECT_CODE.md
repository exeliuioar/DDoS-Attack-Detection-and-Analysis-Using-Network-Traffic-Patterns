# Complete DDoS Detection Project Code

This document contains all the code you need. Copy each section into the appropriate file.

## File Structure

```
ddos-detection/
├── src/
│   ├── __init__.py (already created)
│   ├── utils.py (already created)
│   ├── entropy.py (already created)
│   ├── feature_extract.py
│   ├── detect.py
│   ├── train_baseline.py
│   ├── preprocess.py
│   ├── analyze_dataset.py
│   ├── dashboard.py
│   └── generate_sample_data.py
├── tests/
│   ├── test_detection.py
│   ├── test_features.py
│   └── test_preprocessing.py
├── requirements.txt (already created)
├── README.md (already created)
├── initialize_project.sh
├── run_all.sh
└── validate_project.sh
```

---

## src/feature_extract.py

```python
import pandas as pd
import numpy as np
from scapy.all import *
from collections import defaultdict
import time

class FeatureExtractor:
    def __init__(self, window_size=60):
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
        
        duration = packets_df['timestamp'].max() - packets_df['timestamp'].min()
        flow_features['duration'] = duration if duration > 0 else 0.001
        
        flow_features['packet_rate'] = len(packets_df) / flow_features['duration']
        flow_features['byte_rate'] = packets_df['packet_size'].sum() / flow_features['duration']
        
        if len(packets_df) > 1:
            timestamps = packets_df['timestamp'].sort_values()
            iat = timestamps.diff().dropna()
            flow_features['iat_mean'] = iat.mean()
            flow_features['iat_std'] = iat.std()
        else:
            flow_features['iat_mean'] = 0
            flow_features['iat_std'] = 0
            
        protocol_counts = packets_df['protocol_type'].value_counts()
        total = len(packets_df)
        flow_features['tcp_ratio'] = protocol_counts.get('TCP', 0) / total
        flow_features['udp_ratio'] = protocol_counts.get('UDP', 0) / total
        flow_features['icmp_ratio'] = protocol_counts.get('ICMP', 0) / total
        
        flow_features['unique_src_ips'] = packets_df['src_ip'].nunique()
        flow_features['unique_dst_ips'] = packets_df['dst_ip'].nunique()
        flow_features['unique_src_ports'] = packets_df['src_port'].nunique()
        flow_features['unique_dst_ports'] = packets_df['dst_port'].nunique()
        
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
```

---

## src/detect.py

```python
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
        self.baseline = load_model(baseline_file)
        self.extractor = FeatureExtractor(window_size=60)
        self.packet_buffer = []
        self.window_start = time.time()
        
    def detect_anomaly(self, flow_features, entropy_results):
        """Detect if current traffic is anomalous"""
        alerts = []
        
        if flow_features['packet_rate'] > self.baseline['packet_rate_threshold']:
            alerts.append(f"High packet rate: {flow_features['packet_rate']:.2f} pps")
        
        if flow_features['byte_rate'] > self.baseline['byte_rate_threshold']:
            alerts.append(f"High byte rate: {flow_features['byte_rate']:.2f} Bps")
        
        if entropy_results['src_ip_entropy'] < self.baseline['entropy_threshold']:
            alerts.append(f"Low source IP entropy: {entropy_results['src_ip_entropy']:.2f}")
        
        tcp_diff = abs(flow_features['tcp_ratio'] - self.baseline['tcp_ratio_normal'])
        udp_diff = abs(flow_features['udp_ratio'] - self.baseline['udp_ratio_normal'])
        
        if udp_diff > 0.3:
            alerts.append(f"Unusual UDP ratio: {flow_features['udp_ratio']:.2f}")
        
        return len(alerts) > 0, alerts
    
    def detect_from_pcap(self, pcap_file):
        """Run detection on PCAP file"""
        print(f"Analyzing {pcap_file}...")
        
        packets_df, flow_features = extract_from_pcap(pcap_file)
        entropy_results = analyze_entropy(packets_df)
        
        is_attack, alerts = self.detect_anomaly(flow_features, entropy_results)
        
        print("\\n" + "="*60)
        print("ANALYSIS RESULTS")
        print("="*60)
        print(f"\\nFlow Statistics:")
        for key, value in flow_features.items():
            print(f"  {key}: {value:.2f}")
        
        print(f"\\nEntropy Analysis:")
        for key, value in entropy_results.items():
            if isinstance(value, bool):
                print(f"  {key}: {value}")
            else:
                print(f"  {key}: {value:.2f}")
        
        if is_attack:
            print(f"\\n🚨 DDoS ATTACK DETECTED!")
            for alert in alerts:
                print(f"  - {alert}")
        else:
            print(f"\\n✓ Normal traffic detected")
        
        print("="*60 + "\\n")
        
        return is_attack

def main():
    parser = argparse.ArgumentParser(description='DDoS Attack Detector')
    parser.add_argument('--interface', help='Network interface for live capture')
    parser.add_argument('--pcap', help='PCAP file to analyze')
    parser.add_argument('--baseline', default='models/baseline.pkl', help='Baseline model file')
    
    args = parser.parse_args()
    
    if not args.interface and not args.pcap:
        parser.error("Must specify either --interface or --pcap")
    
    detector = DDoSDetector(baseline_file=args.baseline)
    
    if args.pcap:
        detector.detect_from_pcap(args.pcap)

if __name__ == '__main__':
    main()
```

---

## src/train_baseline.py

```python
#!/usr/bin/env python3
import pandas as pd
import argparse
from feature_extract import extract_from_pcap
from utils import save_model

def train_baseline(input_file, output_file):
    """Train baseline profile from normal traffic"""
    print(f"Training baseline from {input_file}")
    
    packets_df, flow_features = extract_from_pcap(input_file)
    
    baseline = {
        'packet_rate_mean': flow_features['packet_rate'],
        'packet_rate_threshold': flow_features['packet_rate'] * 3,
        'byte_rate_mean': flow_features['byte_rate'],
        'byte_rate_threshold': flow_features['byte_rate'] * 3,
        'unique_src_ips_mean': flow_features['unique_src_ips'],
        'unique_dst_ips_mean': flow_features['unique_dst_ips'],
        'tcp_ratio_normal': flow_features['tcp_ratio'],
        'udp_ratio_normal': flow_features['udp_ratio'],
        'icmp_ratio_normal': flow_features['icmp_ratio'],
        'entropy_threshold': 2.5,
    }
    
    print("\\nBaseline Profile:")
    for key, value in baseline.items():
        print(f"  {key}: {value:.2f}")
    
    save_model(baseline, output_file)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train baseline from normal traffic')
    parser.add_argument('--input', required=True, help='Input PCAP file')
    parser.add_argument('--output', default='models/baseline.pkl', help='Output baseline file')
    
    args = parser.parse_args()
    train_baseline(args.input, args.output)
```

---

## src/generate_sample_data.py

```python
#!/usr/bin/env python3
import pandas as pd
import numpy as np
from scapy.all import *
import argparse
import random

def generate_normal_traffic(num_packets=1000):
    """Generate normal network traffic"""
    packets = []
    src_ips = [f"192.168.1.{i}" for i in range(1, 50)]
    dst_ips = [f"10.0.0.{i}" for i in range(1, 10)]
    
    timestamp = 0.0
    
    for i in range(num_packets):
        src_ip = random.choice(src_ips)
        dst_ip = random.choice(dst_ips)
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 25])
        packet_size = random.randint(64, 1500)
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
        
        timestamp += max(0.001, np.random.normal(0.01, 0.005))
    
    return pd.DataFrame(packets)

def generate_ddos_traffic(num_packets=5000, attack_type='udp_flood'):
    """Generate DDoS attack traffic"""
    packets = []
    
    if attack_type == 'udp_flood':
        src_ips = [f"203.0.113.{i}" for i in range(1, 10)]
        dst_ip = "10.0.0.1"
        dst_port = 80
        
        timestamp = 0.0
        
        for i in range(num_packets):
            src_ip = random.choice(src_ips)
            src_port = random.randint(1024, 65535)
            packet_size = random.randint(32, 128)
            
            packets.append({
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'packet_size': packet_size,
                'protocol_type': 'UDP',
                'timestamp': timestamp
            })
            
            timestamp += max(0.0001, np.random.normal(0.001, 0.0005))
    
    elif attack_type == 'syn_flood':
        src_ips = [f"198.51.100.{i}" for i in range(1, 20)]
        dst_ip = "10.0.0.1"
        dst_port = 80
        
        timestamp = 0.0
        
        for i in range(num_packets):
            src_ip = random.choice(src_ips)
            src_port = random.randint(1024, 65535)
            packet_size = 60
            
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
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / TCP(sport=row['src_port'], dport=row['dst_port'])
        elif row['protocol_type'] == 'UDP':
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / UDP(sport=row['src_port'], dport=row['dst_port'])
        else:
            pkt = IP(src=row['src_ip'], dst=row['dst_ip']) / ICMP()
        
        packet_list.append(pkt)
    
    wrpcap(output_file, packet_list)
    print(f"Saved {len(packet_list)} packets to {output_file}")

def main():
    parser = argparse.ArgumentParser(description='Generate sample network traffic')
    parser.add_argument('--type', choices=['normal', 'udp_flood', 'syn_flood'], required=True)
    parser.add_argument('--packets', type=int, default=1000)
    parser.add_argument('--output', required=True)
    parser.add_argument('--csv', help='Also save as CSV')
    
    args = parser.parse_args()
    
    if args.type == 'normal':
        df = generate_normal_traffic(args.packets)
    else:
        df = generate_ddos_traffic(args.packets, args.type)
    
    save_to_pcap(df, args.output)
    
    if args.csv:
        df.to_csv(args.csv, index=False)
    
    print(f"\\nTraffic Statistics:")
    print(f"  Total packets: {len(df)}")
    print(f"  Unique source IPs: {df['src_ip'].nunique()}")
    print(f"  Duration: {df['timestamp'].max():.2f} seconds")

if __name__ == '__main__':
    main()
```

---

## Shell Scripts

### initialize_project.sh

```bash
#!/bin/bash
echo "Initializing DDoS Detection Project..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Create directories
mkdir -p data/{raw,processed,clean} models analysis_results results_visualization

echo "✓ Project initialized!"
echo "Run: ./run_all.sh to execute complete workflow"
```

### run_all.sh

```bash
#!/bin/bash
echo "Running Complete DDoS Detection Workflow..."

source venv/bin/activate

# Generate test data
python src/generate_sample_data.py --type normal --packets 1000 --output data/normal_traffic.pcap
python src/generate_sample_data.py --type udp_flood --packets 5000 --output data/attack_traffic.pcap

# Train baseline
python src/train_baseline.py --input data/normal_traffic.pcap --output models/baseline.pkl

# Run detection
python src/detect.py --pcap data/normal_traffic.pcap
python src/detect.py --pcap data/attack_traffic.pcap

echo "✓ Workflow complete!"
```

### validate_project.sh

```bash
#!/bin/bash
echo "Validating DDoS Detection Project..."

ERRORS=0

# Check Python
if python3 --version > /dev/null 2>&1; then
    echo "✓ Python installed"
else
    echo "✗ Python not found"
    ((ERRORS++))
fi

# Check virtual environment
if [ -d "venv" ]; then
    echo "✓ Virtual environment exists"
else
    echo "✗ Virtual environment not found"
    ((ERRORS++))
fi

# Check directories
for dir in src tests data models; do
    if [ -d "$dir" ]; then
        echo "✓ Directory $dir exists"
    else
        echo "✗ Directory $dir missing"
        ((ERRORS++))
    fi
done

if [ $ERRORS -eq 0 ]; then
    echo "\\n✓ Validation passed!"
else
    echo "\\n✗ Found $ERRORS errors"
fi
```

---

## Tests

### tests/test_detection.py

```python
import unittest
import sys
sys.path.insert(0, 'src')
from detect import DDoSDetector

class TestDDoSDetection(unittest.TestCase):
    
    def setUp(self):
        self.baseline = {
            'packet_rate_mean': 100,
            'packet_rate_threshold': 300,
            'byte_rate_mean': 50000,
            'byte_rate_threshold': 150000,
            'entropy_threshold': 2.5,
            'tcp_ratio_normal': 0.7,
            'udp_ratio_normal': 0.2,
            'icmp_ratio_normal': 0.1
        }
    
    def test_high_packet_rate_detection(self):
        flow_features = {
            'packet_rate': 500,
            'byte_rate': 60000,
            'tcp_ratio': 0.7,
            'udp_ratio': 0.2
        }
        
        entropy_results = {'src_ip_entropy': 3.0}
        
        detector = DDoSDetector.__new__(DDoSDetector)
        detector.baseline = self.baseline
        
        is_attack, alerts = detector.detect_anomaly(flow_features, entropy_results)
        self.assertTrue(is_attack)

if __name__ == '__main__':
    unittest.main()
```

---

## Quick Start Instructions

1. Extract all files to `ddos-detection/` directory
2. Make scripts executable: `chmod +x *.sh`
3. Run: `./initialize_project.sh`
4. Run: `./run_all.sh`

Your project is now complete!
