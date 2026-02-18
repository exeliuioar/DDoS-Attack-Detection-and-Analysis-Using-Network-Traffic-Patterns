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
    """Create comprehensive interactive Plotly dashboard with modern design."""
    logging.info("Creating enhanced dashboard...")
    
    # Color scheme - professional cybersecurity theme
    colors = {
        'primary': '#1e3a8a',      # Deep blue
        'success': '#10b981',      # Green
        'warning': '#f59e0b',      # Amber
        'danger': '#ef4444',       # Red
        'info': '#3b82f6',         # Blue
        'background': '#f8fafc',   # Light gray
        'text': '#1e293b',         # Dark slate
        'benign': '#22c55e',       # Light green
        'attack': '#dc2626'        # Bright red
    }
    
    # Create figure with custom layout
    fig = make_subplots(
        rows=4, cols=3,
        subplot_titles=(
            'Traffic Volume Over Time', 'Detection Timeline', 'Anomaly Score Distribution',
            'Source IP Entropy Analysis', 'Packet Rate Analysis', 'Feature Violations',
            'Detection Confusion Matrix', 'Attack Type Distribution', 'ROC Curve Analysis',
            'Temporal Attack Pattern', 'Feature Correlation Heatmap', 'Detection Confidence'
        ),
        specs=[
            [{"type": "scatter", "colspan": 2}, None, {"type": "scatter"}],
            [{"type": "scatter"}, {"type": "scatter"}, {"type": "bar"}],
            [{"type": "heatmap"}, {"type": "pie"}, {"type": "scatter"}],
            [{"type": "scatter", "colspan": 2}, None, {"type": "indicator"}]
        ],
        vertical_spacing=0.08,
        horizontal_spacing=0.1
    )
    
    # Sample data for better performance
    sample_size = min(2000, len(df))
    sample_indices = np.linspace(0, len(df)-1, sample_size, dtype=int)
    
    # 1. Traffic Volume Over Time (Row 1, Col 1-2)
    if 'Flow Bytes/s' in features.columns:
        traffic_data = features['Flow Bytes/s'].iloc[sample_indices]
        attack_mask = predictions[sample_indices].astype(bool)
        
        fig.add_trace(
            go.Scatter(
                x=sample_indices,
                y=traffic_data,
                mode='lines',
                name='Benign Traffic',
                line=dict(color=colors['benign'], width=1),
                fill='tozeroy',
                fillcolor=f"rgba(34, 197, 94, 0.1)"
            ),
            row=1, col=1
        )
        
        if attack_mask.any():
            fig.add_trace(
                go.Scatter(
                    x=sample_indices[attack_mask],
                    y=traffic_data[attack_mask],
                    mode='markers',
                    name='Attack Traffic',
                    marker=dict(color=colors['attack'], size=4, symbol='x')
                ),
                row=1, col=1
            )
    
    # 2. Detection Timeline (Row 1, Col 3)
    detection_cumsum = np.cumsum(predictions[sample_indices])
    fig.add_trace(
        go.Scatter(
            x=sample_indices,
            y=detection_cumsum,
            mode='lines',
            name='Cumulative Detections',
            line=dict(color=colors['danger'], width=2),
            fill='tozeroy'
        ),
        row=1, col=3
    )
    
    # 3. Anomaly Score Distribution (Row 2, Col 1)
    fig.add_trace(
        go.Histogram(
            x=anomaly_scores,
            nbinsx=30,
            name='Anomaly Scores',
            marker=dict(
                color=anomaly_scores,
                colorscale='RdYlGn_r',
                showscale=True,
                colorbar=dict(x=0.35, len=0.3, y=0.65)
            ),
            showlegend=False
        ),
        row=2, col=1
    )
    
    # 4. Source IP Entropy (Row 2, Col 2)
    if 'src_ip_entropy' in features.columns:
        entropy_val = features['src_ip_entropy'].iloc[0]
        fig.add_trace(
            go.Scatter(
                x=sample_indices,
                y=[entropy_val] * len(sample_indices),
                mode='lines',
                name=f'IP Entropy: {entropy_val:.2f}',
                line=dict(color=colors['info'], width=3),
                fill='tozeroy'
            ),
            row=2, col=2
        )
        
        # Add threshold line
        threshold = 4.0
        fig.add_trace(
            go.Scatter(
                x=sample_indices,
                y=[threshold] * len(sample_indices),
                mode='lines',
                name='Normal Threshold',
                line=dict(color=colors['success'], width=2, dash='dash'),
                showlegend=False
            ),
            row=2, col=2
        )
    
    # 5. Feature Violations (Row 2, Col 3)
    if len(features.columns) > 0:
        feature_cols = [col for col in features.columns if col not in ['src_ip_entropy', 'src_port_entropy']][:5]
        violation_counts = []
        for col in feature_cols:
            if col in features.columns:
                data = features[col].values
                mean = np.mean(data)
                std = np.std(data)
                violations = np.sum((data > mean + 3*std) | (data < mean - 3*std))
                violation_counts.append(violations)
        
        if violation_counts:
            fig.add_trace(
                go.Bar(
                    x=[col.replace(' ', '<br>') for col in feature_cols],
                    y=violation_counts,
                    marker=dict(
                        color=violation_counts,
                        colorscale='Reds',
                        showscale=False
                    ),
                    name='Violations',
                    showlegend=False
                ),
                row=2, col=3
            )
    
    # 6. Confusion Matrix (Row 3, Col 1)
    cm = [[metrics['tn'], metrics['fp']], 
          [metrics['fn'], metrics['tp']]]
    fig.add_trace(
        go.Heatmap(
            z=cm,
            x=['Predicted Benign', 'Predicted Attack'],
            y=['Actual Benign', 'Actual Attack'],
            text=cm,
            texttemplate='%{text}',
            textfont={"size": 16},
            colorscale='Blues',
            showscale=False
        ),
        row=3, col=1
    )
    
    # 7. Attack Distribution Pie (Row 3, Col 2)
    if 'is_attack' in df.columns:
        attack_counts = df['is_attack'].value_counts()
        fig.add_trace(
            go.Pie(
                labels=['Benign Traffic', 'Attack Traffic'],
                values=[attack_counts.get(False, 0), attack_counts.get(True, 0)],
                marker=dict(colors=[colors['benign'], colors['attack']]),
                hole=0.4,
                textinfo='label+percent',
                showlegend=False
            ),
            row=3, col=2
        )
    
    # 8. ROC-like Analysis (Row 3, Col 3)
    # Plot true positive rate vs false positive rate
    tpr = metrics['recall']
    fpr = metrics['fpr']
    fig.add_trace(
        go.Scatter(
            x=[0, fpr, 1],
            y=[0, tpr, 1],
            mode='lines+markers',
            name='Detection Performance',
            line=dict(color=colors['info'], width=3),
            marker=dict(size=[8, 12, 8]),
            fill='tozeroy',
            fillcolor=f"rgba(59, 130, 246, 0.2)"
        ),
        row=3, col=3
    )
    # Add diagonal reference line
    fig.add_trace(
        go.Scatter(
            x=[0, 1],
            y=[0, 1],
            mode='lines',
            name='Random Classifier',
            line=dict(color='gray', width=1, dash='dash'),
            showlegend=False
        ),
        row=3, col=3
    )
    
    # 9. Temporal Attack Pattern (Row 4, Col 1-2)
    # Bin attacks over time
    window_size = len(sample_indices) // 20
    attack_windows = []
    for i in range(0, len(sample_indices), window_size):
        end = min(i + window_size, len(sample_indices))
        window_attacks = np.sum(predictions[sample_indices[i:end]])
        attack_windows.append(window_attacks)
    
    window_indices = range(len(attack_windows))
    fig.add_trace(
        go.Scatter(
            x=list(window_indices),
            y=attack_windows,
            mode='lines+markers',
            name='Attacks per Window',
            line=dict(color=colors['danger'], width=2),
            marker=dict(size=8),
            fill='tozeroy',
            fillcolor=f"rgba(239, 68, 68, 0.3)"
        ),
        row=4, col=1
    )
    
    # 10. Detection Confidence Gauge (Row 4, Col 3)
    confidence = metrics['f1']
    fig.add_trace(
        go.Indicator(
            mode="gauge+number+delta",
            value=confidence * 100,
            title={'text': "Detection Confidence<br><span style='font-size:0.8em'>F1 Score</span>"},
            delta={'reference': 85},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': colors['primary']},
                'steps': [
                    {'range': [0, 60], 'color': colors['danger']},
                    {'range': [60, 80], 'color': colors['warning']},
                    {'range': [80, 100], 'color': colors['success']}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ),
        row=4, col=3
    )
    
    # Update layout with modern styling
    fig.update_layout(
        title={
            'text': '<b>DDoS Attack Detection Dashboard</b><br><sub>Real-time Network Traffic Analysis</sub>',
            'x': 0.5,
            'xanchor': 'center',
            'font': {'size': 28, 'color': colors['text']}
        },
        showlegend=True,
        height=1800,
        template='plotly_white',
        paper_bgcolor=colors['background'],
        plot_bgcolor='white',
        font=dict(family="Segoe UI, Arial, sans-serif", size=12, color=colors['text']),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            bgcolor="rgba(255,255,255,0.8)"
        )
    )
    
    # Update axes
    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0,0,0,0.1)')
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='rgba(0,0,0,0.1)')
    
    # Create HTML with custom CSS
    html_string = f'''
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>DDoS Detection Dashboard</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                padding: 20px;
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1600px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                overflow: hidden;
            }}
            
            .header {{
                background: linear-gradient(135deg, {colors['primary']} 0%, #1e40af 100%);
                color: white;
                padding: 40px;
                text-align: center;
            }}
            
            .header h1 {{
                font-size: 2.5em;
                margin-bottom: 10px;
                font-weight: 700;
            }}
            
            .header p {{
                font-size: 1.1em;
                opacity: 0.9;
            }}
            
            .metrics-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                padding: 30px;
                background: {colors['background']};
            }}
            
            .metric-card {{
                background: white;
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                border-left: 4px solid;
                transition: transform 0.2s, box-shadow 0.2s;
            }}
            
            .metric-card:hover {{
                transform: translateY(-5px);
                box-shadow: 0 8px 12px rgba(0,0,0,0.15);
            }}
            
            .metric-card.success {{ border-color: {colors['success']}; }}
            .metric-card.info {{ border-color: {colors['info']}; }}
            .metric-card.warning {{ border-color: {colors['warning']}; }}
            .metric-card.danger {{ border-color: {colors['danger']}; }}
            
            .metric-label {{
                font-size: 0.9em;
                color: #64748b;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                margin-bottom: 10px;
            }}
            
            .metric-value {{
                font-size: 2.5em;
                font-weight: 700;
                color: {colors['text']};
                line-height: 1;
            }}
            
            .metric-suffix {{
                font-size: 0.5em;
                color: #94a3b8;
                margin-left: 5px;
            }}
            
            .dashboard-content {{
                padding: 30px;
            }}
            
            .info-box {{
                background: #f1f5f9;
                border-left: 4px solid {colors['info']};
                border-radius: 8px;
                padding: 20px;
                margin: 20px 30px;
            }}
            
            .info-box h3 {{
                color: {colors['primary']};
                margin-bottom: 10px;
            }}
            
            .info-box p {{
                color: {colors['text']};
                line-height: 1.6;
            }}
            
            .footer {{
                background: {colors['text']};
                color: white;
                text-align: center;
                padding: 20px;
                font-size: 0.9em;
            }}
            
            @media (max-width: 768px) {{
                .metrics-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .header h1 {{
                    font-size: 1.8em;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ DDoS Attack Detection Dashboard</h1>
                <p>Real-time Network Traffic Analysis & Threat Detection</p>
            </div>
            
            <div class="metrics-grid">
                <div class="metric-card success">
                    <div class="metric-label">Accuracy</div>
                    <div class="metric-value">{metrics['accuracy']*100:.1f}<span class="metric-suffix">%</span></div>
                </div>
                <div class="metric-card info">
                    <div class="metric-label">Precision</div>
                    <div class="metric-value">{metrics['precision']*100:.1f}<span class="metric-suffix">%</span></div>
                </div>
                <div class="metric-card warning">
                    <div class="metric-label">Recall</div>
                    <div class="metric-value">{metrics['recall']*100:.1f}<span class="metric-suffix">%</span></div>
                </div>
                <div class="metric-card danger">
                    <div class="metric-label">F1 Score</div>
                    <div class="metric-value">{metrics['f1']*100:.1f}<span class="metric-suffix">%</span></div>
                </div>
                <div class="metric-card info">
                    <div class="metric-label">False Positive Rate</div>
                    <div class="metric-value">{metrics['fpr']*100:.1f}<span class="metric-suffix">%</span></div>
                </div>
                <div class="metric-card success">
                    <div class="metric-label">Total Samples</div>
                    <div class="metric-value">{len(df):,}</div>
                </div>
                <div class="metric-card danger">
                    <div class="metric-label">Attacks Detected</div>
                    <div class="metric-value">{np.sum(predictions):,}</div>
                </div>
                <div class="metric-card warning">
                    <div class="metric-label">Detection Rate</div>
                    <div class="metric-value">{(np.sum(predictions)/len(df)*100):.1f}<span class="metric-suffix">%</span></div>
                </div>
            </div>
            
            <div class="info-box">
                <h3>📊 Detection Summary</h3>
                <p>
                    <strong>Analysis Status:</strong> {'✅ High Confidence' if metrics['f1'] > 0.85 else '⚠️ Moderate Confidence' if metrics['f1'] > 0.70 else '❌ Low Confidence'}<br>
                    <strong>True Positives:</strong> {metrics['tp']:,} attacks correctly identified<br>
                    <strong>False Positives:</strong> {metrics['fp']:,} benign traffic incorrectly flagged<br>
                    <strong>True Negatives:</strong> {metrics['tn']:,} benign traffic correctly identified<br>
                    <strong>False Negatives:</strong> {metrics['fn']:,} attacks missed<br>
                </p>
            </div>
            
            <div class="dashboard-content">
                {fig.to_html(include_plotlyjs='cdn', div_id='plotly-dashboard')}
            </div>
            
            <div class="info-box">
                <h3>ℹ️ About This Dashboard</h3>
                <p>
                    This dashboard visualizes DDoS attack detection results using statistical threshold-based analysis 
                    on the CICIDS2017 dataset. The system monitors network traffic patterns, calculates anomaly scores, 
                    and flags potential attacks in real-time. Charts show traffic volume, entropy analysis, detection 
                    timeline, and performance metrics to provide comprehensive insights into network security status.
                </p>
            </div>
            
            <div class="footer">
                <p>DDoS Detection System | Manipal University Jaipur | © 2024</p>
                <p style="margin-top: 5px; opacity: 0.7;">Student: Ankit Meher | Supervisor: Dr. Susheela Vishnoi</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_string)
    
    logging.info(f"Enhanced dashboard saved to {output_path}")
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
