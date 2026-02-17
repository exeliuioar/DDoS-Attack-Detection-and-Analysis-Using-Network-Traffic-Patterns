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
