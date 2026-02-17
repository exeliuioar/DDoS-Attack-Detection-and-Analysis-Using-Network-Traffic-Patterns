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
