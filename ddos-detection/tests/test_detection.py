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
