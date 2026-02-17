#!/usr/bin/env python3
import argparse
import os
import pickle
import logging
import webbrowser
from pathlib import Path
import pandas as pd
import numpy as np
from scipy import stats
from scapy.all import rdpcap, IP, TCP, UDP
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from tqdm import tqdm

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ensure_dirs():
    Path('data').mkdir(exist_ok=True)
    Path('models').mkdir(exist_ok=True)
    Path('results').mkdir(exist_ok=True)

def load_cicids2017(csv_path, chunksize=50000):
    """Load CICIDS2017 dataset in chunks to handle large files."""
    if not os.path.exists(csv_path):
        logging.error(f"Dataset not found at {csv_path}")
        print("\n" + "="*80)
        print("CICIDS2017 DATASET REQUIRED")
        print("="*80)
        print("Download from: https://www.unb.ca/cic/datasets/ids-2017.html")
        print("Extract and place CSV files in ./data/ folder")
        print("Recommended file: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        print("="*80 + "\n")
        return None
    
    logging.info(f"Loading dataset from {csv_path}...")
    chunks = []
    try:
        for chunk in tqdm(pd.read_csv(csv_path, chunksize=chunksize, encoding='utf-8', low_memory=False), 
                         desc="Reading CSV"):
            chunk.columns = chunk.columns.str.strip()
            chunks.append(chunk)
        df = pd.concat(chunks, ignore_index=True)
        logging.info(f"Loaded {len(df)} records")
        return df
    except Exception as e:
        logging.error(f"Error loading dataset: {e}")
        return None

def preprocess_data(df):
    """Clean and prepare dataset."""
    logging.info("Preprocessing data...")
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.fillna(0)
    
    if 'Label' in df.columns:
        df['is_attack'] = df['Label'].str.strip().str.lower() != 'benign'
    elif ' Label' in df.columns:
        df['is_attack'] = df[' Label'].str.strip().str.lower() != 'benign'
    else:
        logging.warning("No Label column found, assuming all benign")
        df['is_attack'] = False
    
    return df

def extract_features(df):
    """Extract statistical features for detection."""
    features = {}
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    flow_features = [
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
        'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
        'Fwd IAT Mean', 'Bwd IAT Mean', 'Fwd Packet Length Mean', 
        'Bwd Packet Length Mean', 'Packet Length Mean', 'Packet Length Std'
    ]
    
    for col in flow_features:
        clean_col = col.strip()
        matching = [c for c in numeric_cols if c.strip() == clean_col or c.strip() == ' ' + clean_col]
        if matching:
            features[clean_col] = df[matching[0]].values
    
    if 'Source IP' in df.columns:
        features['src_ip_entropy'] = calculate_entropy(df['Source IP'])
    elif ' Source IP' in df.columns:
        features['src_ip_entropy'] = calculate_entropy(df[' Source IP'])
    
    if 'Source Port' in df.columns:
        features['src_port_entropy'] = calculate_entropy(df['Source Port'])
    elif ' Source Port' in df.columns:
        features['src_port_entropy'] = calculate_entropy(df[' Source Port'])
    
    return pd.DataFrame(features)

def calculate_entropy(series):
    """Calculate Shannon entropy for a series."""
    value_counts = series.value_counts(normalize=True)
    return -np.sum(value_counts * np.log2(value_counts + 1e-10))

def train_baseline(benign_features, model_path='models/baseline.pkl'):
    """Train baseline thresholds on benign traffic."""
    logging.info("Training baseline model...")
    thresholds = {}
    
    for col in benign_features.columns:
        data = benign_features[col].values
        mean = np.mean(data)
        std = np.std(data)
        thresholds[col] = {
            'mean': mean,
            'std': std,
            'upper': mean + 3 * std,
            'lower': max(0, mean - 3 * std)
        }
    
    with open(model_path, 'wb') as f:
        pickle.dump(thresholds, f)
    
    logging.info(f"Baseline model saved to {model_path}")
    return thresholds

def detect_anomalies(features, thresholds, adaptive=True):
    """Detect anomalies using statistical thresholds."""
    anomaly_scores = np.zeros(len(features))
    
    for col in features.columns:
        if col in thresholds:
            data = features[col].values
            upper = thresholds[col]['upper']
            lower = thresholds[col]['lower']
            
            if adaptive:
                recent_mean = np.mean(data[-1000:]) if len(data) > 1000 else np.mean(data)
                recent_std = np.std(data[-1000:]) if len(data) > 1000 else np.std(data)
                upper = recent_mean + 3 * recent_std
                lower = max(0, recent_mean - 3 * recent_std)
            
            violations = (data > upper) | (data < lower)
            anomaly_scores += violations.astype(int)
    
    predictions = anomaly_scores >= 2
    return predictions, anomaly_scores

def calculate_metrics(y_true, y_pred):
    """Calculate detection metrics."""
    tp = np.sum((y_true == 1) & (y_pred == 1))
    tn = np.sum((y_true == 0) & (y_pred == 0))
    fp = np.sum((y_true == 0) & (y_pred == 1))
    fn = np.sum((y_true == 1) & (y_pred == 0))
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fpr': fpr,
        'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn
    }

def process_pcap(pcap_path, thresholds):
    """Process PCAP file for detection."""
    logging.info(f"Processing PCAP file: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
        records = []
        
        for pkt in tqdm(packets, desc="Parsing packets"):
            if IP in pkt:
                record = {
                    'src_ip': pkt[IP].src,
                    'dst_ip': pkt[IP].dst,
                    'protocol': pkt[IP].proto,
                    'length': len(pkt)
                }
                if TCP in pkt:
                    record['src_port'] = pkt[TCP].sport
                    record['dst_port'] = pkt[TCP].dport
                elif UDP in pkt:
                    record['src_port'] = pkt[UDP].sport
                    record['dst_port'] = pkt[UDP].dport
                records.append(record)
        
        df = pd.DataFrame(records)
        logging.info(f"Processed {len(df)} packets")
        return df
    except Exception as e:
        logging.error(f"Error processing PCAP: {e}")
        return None

def create_dashboard(df, features, predictions, anomaly_scores, metrics, output_path='dashboard.html'):
    """Create interactive Plotly dashboard."""
    logging.info("Creating dashboard...")
    
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=('Traffic Volume Over Time', 'Entropy Analysis',
                       'Anomaly Scores Distribution', 'Detection Timeline',
                       'Performance Metrics', 'Attack Distribution'),
        specs=[[{"type": "scatter"}, {"type": "scatter"}],
               [{"type": "histogram"}, {"type": "scatter"}],
               [{"type": "bar"}, {"type": "pie"}]]
    )
    
    sample_indices = np.linspace(0, len(df)-1, min(1000, len(df)), dtype=int)
    
    if 'Flow Bytes/s' in features.columns:
        fig.add_trace(
            go.Scatter(x=sample_indices, y=features['Flow Bytes/s'].iloc[sample_indices],
                      mode='lines', name='Traffic Volume', line=dict(color='blue')),
            row=1, col=1
        )
    
    if 'src_ip_entropy' in features.columns:
        fig.add_trace(
            go.Scatter(x=sample_indices, 
                      y=[features['src_ip_entropy'].iloc[0]] * len(sample_indices),
                      mode='lines', name='Source IP Entropy', line=dict(color='green')),
            row=1, col=2
        )
    
    fig.add_trace(
        go.Histogram(x=anomaly_scores, nbinsx=50, name='Anomaly Scores',
                    marker=dict(color='orange')),
        row=2, col=1
    )
    
    attack_mask = predictions.astype(bool)
    fig.add_trace(
        go.Scatter(x=sample_indices, y=predictions[sample_indices],
                  mode='markers', name='Detections',
                  marker=dict(color='red', size=3)),
        row=2, col=2
    )
    
    metrics_labels = ['Accuracy', 'Precision', 'Recall', 'F1 Score']
    metrics_values = [metrics['accuracy'], metrics['precision'], 
                     metrics['recall'], metrics['f1']]
    fig.add_trace(
        go.Bar(x=metrics_labels, y=metrics_values, 
               marker=dict(color=['green', 'blue', 'orange', 'purple'])),
        row=3, col=1
    )
    
    if 'is_attack' in df.columns:
        attack_counts = df['is_attack'].value_counts()
        fig.add_trace(
            go.Pie(labels=['Benign', 'Attack'], 
                  values=[attack_counts.get(False, 0), attack_counts.get(True, 0)]),
            row=3, col=2
        )
    
    fig.update_layout(
        title_text="DDoS Detection Dashboard",
        showlegend=True,
        height=1200,
        template='plotly_white'
    )
    
    fig.write_html(output_path)
    logging.info(f"Dashboard saved to {output_path}")
    return output_path

def full_pipeline(csv_path, adaptive=True):
    """Run complete detection pipeline."""
    ensure_dirs()
    
    df = load_cicids2017(csv_path)
    if df is None:
        return
    
    df = preprocess_data(df)
    
    benign_df = df[~df['is_attack']]
    logging.info(f"Benign samples: {len(benign_df)}, Attack samples: {len(df) - len(benign_df)}")
    
    benign_features = extract_features(benign_df)
    thresholds = train_baseline(benign_features)
    
    all_features = extract_features(df)
    predictions, anomaly_scores = detect_anomalies(all_features, thresholds, adaptive)
    
    metrics = calculate_metrics(df['is_attack'].values, predictions)
    
    logging.info("\n" + "="*60)
    logging.info("DETECTION RESULTS")
    logging.info("="*60)
    logging.info(f"Accuracy:  {metrics['accuracy']:.4f}")
    logging.info(f"Precision: {metrics['precision']:.4f}")
    logging.info(f"Recall:    {metrics['recall']:.4f}")
    logging.info(f"F1 Score:  {metrics['f1']:.4f}")
    logging.info(f"FPR:       {metrics['fpr']:.4f}")
    logging.info(f"TP: {metrics['tp']}, TN: {metrics['tn']}, FP: {metrics['fp']}, FN: {metrics['fn']}")
    logging.info("="*60 + "\n")
    
    results_df = pd.DataFrame({
        'prediction': predictions,
        'anomaly_score': anomaly_scores,
        'actual_attack': df['is_attack']
    })
    results_df.to_csv('results/detection_results.csv', index=False)
    
    dashboard_path = create_dashboard(df, all_features, predictions, anomaly_scores, metrics)
    
    webbrowser.open('file://' + os.path.abspath(dashboard_path))
    logging.info("Dashboard opened in browser")

def main():
    parser = argparse.ArgumentParser(description='DDoS Detection System')
    parser.add_argument('--mode', choices=['full', 'baseline', 'detect', 'pcap'],
                       default='full', help='Operation mode')
    parser.add_argument('--csv', default='data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
                       help='Path to CICIDS2017 CSV file')
    parser.add_argument('--pcap', help='Path to PCAP file for processing')
    parser.add_argument('--model', default='models/baseline.pkl', help='Baseline model path')
    parser.add_argument('--adaptive', action='store_true', default=True,
                       help='Use adaptive thresholds')
    
    args = parser.parse_args()
    
    if args.mode == 'full':
        full_pipeline(args.csv, args.adaptive)
    
    elif args.mode == 'baseline':
        ensure_dirs()
        df = load_cicids2017(args.csv)
        if df is not None:
            df = preprocess_data(df)
            benign_df = df[~df['is_attack']]
            features = extract_features(benign_df)
            train_baseline(features, args.model)
    
    elif args.mode == 'detect':
        ensure_dirs()
        df = load_cicids2017(args.csv)
        if df is not None:
            df = preprocess_data(df)
            features = extract_features(df)
            
            with open(args.model, 'rb') as f:
                thresholds = pickle.load(f)
            
            predictions, scores = detect_anomalies(features, thresholds, args.adaptive)
            metrics = calculate_metrics(df['is_attack'].values, predictions)
            
            logging.info(f"Accuracy: {metrics['accuracy']:.4f}, F1: {metrics['f1']:.4f}")
    
    elif args.mode == 'pcap':
        if not args.pcap:
            logging.error("--pcap argument required for pcap mode")
            return
        
        with open(args.model, 'rb') as f:
            thresholds = pickle.load(f)
        
        process_pcap(args.pcap, thresholds)

if __name__ == '__main__':
    main()
