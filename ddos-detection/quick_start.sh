#!/bin/bash

echo "DDoS Detection - Quick Start"

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q --upgrade pip
pip install -q -r requirements.txt

mkdir -p data/{raw,processed,clean} models analysis_results

python src/generate_sample_data.py --type normal --packets 500 --output data/normal_traffic.pcap
python src/generate_sample_data.py --type udp_flood --packets 2000 --output data/attack_traffic.pcap

python src/train_baseline.py --input data/normal_traffic.pcap --output models/baseline.pkl

python src/detect.py --pcap data/attack_traffic.pcap

echo ""
echo "Quick Start Complete!"
echo "Try: python src/dashboard.py --port 8080"
