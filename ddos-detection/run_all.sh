#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║     DDoS Attack Detection - Complete Workflow Runner      ║"
echo "╚════════════════════════════════════════════════════════════╝"

START_TIME=$(date +%s)

echo ""
echo "PHASE 1: Environment Setup"
source venv/bin/activate 2>/dev/null || true

echo ""
echo "PHASE 2: Generate Test Data"
python src/generate_sample_data.py --type normal --packets 1000 --output data/normal_traffic.pcap --csv data/normal_traffic.csv
python src/generate_sample_data.py --type udp_flood --packets 5000 --output data/udp_flood_attack.pcap --csv data/udp_flood_attack.csv

echo ""
echo "PHASE 3: Train Baseline Model"
python src/train_baseline.py --input data/normal_traffic.pcap --output models/baseline.pkl

echo ""
echo "PHASE 4: Run Detection Tests"
python src/detect.py --pcap data/normal_traffic.pcap --baseline models/baseline.pkl
python src/detect.py --pcap data/udp_flood_attack.pcap --baseline models/baseline.pkl

echo ""
echo "PHASE 5: Run Unit Tests"
python -m pytest tests/ -v

echo ""
echo "PHASE 6: Generate Visualizations"
python src/visualize_results.py --output results_visualization

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║           ALL PHASES COMPLETED SUCCESSFULLY!               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Total execution time: ${DURATION} seconds"
echo ""
echo "Next steps:"
echo "  1. Launch dashboard: python src/dashboard.py --port 8080"
echo "  2. View visualizations: open results_visualization/"
