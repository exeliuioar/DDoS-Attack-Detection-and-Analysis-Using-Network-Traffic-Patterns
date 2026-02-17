#!/bin/bash

# Create test files
cat > tests/test_detection.py << 'EOF'
import unittest
import sys
sys.path.insert(0, 'src')
from detect import DDoSDetector
import pandas as pd

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
EOF

cat > tests/test_features.py << 'EOF'
import unittest
import sys
sys.path.insert(0, 'src')
from feature_extract import FeatureExtractor
import pandas as pd

class TestFeatureExtraction(unittest.TestCase):
    def setUp(self):
        self.extractor = FeatureExtractor(window_size=60)
        self.packets_df = pd.DataFrame({
            'src_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.1'],
            'dst_ip': ['10.0.0.1', '10.0.0.1', '10.0.0.1'],
            'src_port': [5000, 5001, 5000],
            'dst_port': [80, 80, 80],
            'packet_size': [100, 150, 120],
            'protocol_type': ['TCP', 'TCP', 'UDP'],
            'timestamp': [1.0, 1.5, 2.0]
        })
    
    def test_packet_rate_calculation(self):
        features = self.extractor.extract_flow_features(self.packets_df)
        self.assertAlmostEqual(features['packet_rate'], 3.0, places=1)

if __name__ == '__main__':
    unittest.main()
EOF

cat > tests/test_preprocessing.py << 'EOF'
import unittest
import pandas as pd
import numpy as np

class TestPreprocessing(unittest.TestCase):
    def test_missing_value_handling(self):
        df = pd.DataFrame({'A': [1, np.nan, 3], 'B': [4, 5, np.nan]})
        df_filled = df.fillna(0)
        self.assertEqual(df_filled['A'][1], 0)
    
    def test_duplicate_removal(self):
        df = pd.DataFrame({'A': [1, 2, 1], 'B': [3, 4, 3]})
        df_no_dup = df.drop_duplicates()
        self.assertEqual(len(df_no_dup), 2)

if __name__ == '__main__':
    unittest.main()
EOF

touch tests/__init__.py

# Create shell scripts
cat > run_all.sh << 'EOF'
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
EOF

cat > quick_start.sh << 'EOF'
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
EOF

cat > validate_project.sh << 'EOF'
#!/bin/bash

echo "Validating DDoS Detection Project..."
ERRORS=0

echo -n "Checking Python version... "
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python $PYTHON_VERSION"

echo -n "Checking virtual environment... "
if [ -d "venv" ]; then
    echo "✓ Found"
else
    echo "✗ Not found"
    ((ERRORS++))
fi

echo "Checking directories..."
for dir in src tests notebooks docs data models; do
    echo -n "  $dir... "
    if [ -d "$dir" ]; then
        echo "✓"
    else
        echo "✗ Missing"
        ((ERRORS++))
    fi
done

if [ $ERRORS -eq 0 ]; then
    echo "✓ Project validation passed!"
else
    echo "✗ Found $ERRORS error(s)"
fi
EOF

cat > initialize_project.sh << 'EOF'
#!/bin/bash

echo "DDoS Detection Project - Initial Setup"

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed"
    exit 1
fi

echo "✓ Python 3 found: $(python3 --version)"

python3 -m venv venv
source venv/bin/activate

pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

mkdir -p data/{raw,processed,clean} models analysis_results results_visualization

chmod +x run_all.sh quick_start.sh validate_project.sh
chmod +x src/*.py

echo ""
echo "Initialization Complete!"
echo "Next: ./run_all.sh"
EOF

chmod +x *.sh

echo "All test and script files created!"
