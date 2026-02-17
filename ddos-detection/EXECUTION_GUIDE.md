# Complete Execution Guide

## Step-by-Step Instructions

### Phase 1: Initial Setup (10 minutes)

```bash
# 1. Clone repository
git clone https://github.com/yourusername/ddos-detection.git
cd ddos-detection

# 2. Run initialization
./initialize_project.sh
```

### Phase 2: Run Complete Workflow (20 minutes)

```bash
./run_all.sh
```

This will:
- Generate test traffic
- Train baseline model
- Run detection tests
- Execute unit tests
- Generate visualizations

### Phase 3: View Results

```bash
# View summary
cat EXECUTION_SUMMARY.txt

# View visualizations
ls results_visualization/

# Launch dashboard
python src/dashboard.py --port 8080
```

## Troubleshooting

### Permission Denied
```bash
# Use sudo for live capture
sudo python src/detect.py --interface eth0
```

### Module Not Found
```bash
# Activate virtual environment
source venv/bin/activate
pip install -r requirements.txt
```

## Expected Timeline

| Phase | Duration |
|-------|----------|
| Setup | 10 min |
| Workflow | 20 min |
| Analysis | 30 min |
| **Total** | **~1 hour** |
