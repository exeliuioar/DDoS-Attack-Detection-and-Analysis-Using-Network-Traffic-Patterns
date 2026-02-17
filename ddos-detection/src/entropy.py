import numpy as np
from scipy.stats import entropy
from collections import Counter

def calculate_entropy(data):
    """
    Calculate Shannon entropy of data
    Low entropy indicates concentrated sources (potential DDoS)
    """
    if len(data) == 0:
        return 0
    
    # Count occurrences
    counts = Counter(data)
    total = len(data)
    
    # Calculate probabilities
    probabilities = np.array([count/total for count in counts.values()])
    
    # Calculate entropy
    return entropy(probabilities, base=2)

def analyze_entropy(packets_df, threshold=2.0):
    """
    Analyze entropy of source IPs, destination IPs, and ports
    Returns True if DDoS detected (low entropy)
    """
    results = {}
    
    # Source IP entropy
    src_ip_entropy = calculate_entropy(packets_df['src_ip'].values)
    results['src_ip_entropy'] = src_ip_entropy
    
    # Destination IP entropy
    dst_ip_entropy = calculate_entropy(packets_df['dst_ip'].values)
    results['dst_ip_entropy'] = dst_ip_entropy
    
    # Source port entropy
    src_port_entropy = calculate_entropy(packets_df['src_port'].values)
    results['src_port_entropy'] = src_port_entropy
    
    # Destination port entropy
    dst_port_entropy = calculate_entropy(packets_df['dst_port'].values)
    results['dst_port_entropy'] = dst_port_entropy
    
    # Detection logic
    # Low source IP entropy + high packet rate = DDoS
    results['ddos_detected'] = src_ip_entropy < threshold
    
    return results
