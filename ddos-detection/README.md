# DDoS Attack Detection and Analysis Using Network Traffic Patterns

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Research-yellow.svg)]()

> A statistical network traffic analysis system for detecting Distributed Denial of Service (DDoS) attacks using threshold-based methods and entropy analysis.

## 🎯 Overview

This project implements a DDoS attack detection system that analyzes network traffic patterns using statistical methods. Unlike machine learning-based approaches, this system employs threshold-based detection and entropy analysis to identify anomalous traffic patterns, making it lightweight, accessible, and suitable for educational and small-scale deployments.

## ✨ Features

- **Real-Time Traffic Analysis**: Continuous monitoring and analysis of network packets
- **Statistical Profiling**: Baseline establishment for normal traffic patterns
- **Threshold-Based Detection**: Anomaly identification without ML complexity
- **Entropy Analysis**: Detection of distribution changes in source IPs and ports
- **Multi-Protocol Support**: Analysis of TCP, UDP, ICMP traffic
- **Visualization Dashboard**: Real-time display of traffic statistics and alerts
- **Low False Positive Rate**: Optimized thresholds minimize false alarms
- **Lightweight Design**: Minimal resource consumption

## 🚀 Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/yourusername/ddos-detection.git
cd ddos-detection

# 2. Initialize project
./initialize_project.sh

# 3. Run complete workflow
./run_all.sh

# 4. View results
cat EXECUTION_SUMMARY.txt
```

## 📊 Results

### Performance Metrics

| Metric | Value |
|--------|-------|
| **Detection Accuracy** | 87.5% |
| **Precision** | 89.2% |
| **Recall** | 85.8% |
| **F1-Score** | 87.4% |
| **False Positive Rate** | 8.5% |
| **Detection Time** | 3.2 sec |

## 📁 Project Structure

```
ddos-detection/
├── src/                    # Source code
│   ├── detect.py          # Main detection script
│   ├── feature_extract.py # Feature extraction
│   ├── entropy.py         # Entropy analysis
│   ├── train_baseline.py  # Baseline training
│   └── dashboard.py       # Visualization dashboard
├── tests/                 # Unit tests
├── data/                  # Datasets
├── models/                # Trained models
├── docs/                  # Documentation
└── notebooks/             # Jupyter notebooks
```

## 💻 Usage

### Basic Detection

```bash
# Run on PCAP file
python src/detect.py --pcap data/sample_traffic.pcap

# Run on live interface (requires root)
sudo python src/detect.py --interface eth0

# Launch dashboard
python src/dashboard.py --port 8080
```

## 🎓 Academic Information

**Institution**: Manipal University Jaipur  
**Student**: Ankit Meher  
**Registration No**: 23FE10CSE00332  
**Supervisor**: Dr. Susheela Vishnoi  

## 📄 License

This project is licensed under the MIT License.

## 📧 Contact

**Ankit Meher**  
- Email: ankit.meher@example.com
- GitHub: [@ankitmeher](https://github.com/ankitmeher)

---

⭐ If you find this project useful, please consider giving it a star!
