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
