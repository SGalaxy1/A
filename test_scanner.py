import unittest
import os
import json
from unittest.mock import patch, mock_open

# Assuming scanner.py is in the same directory or accessible via PYTHONPATH
from scanner import generate_random_header_case, generate_url_path_variation

class TestScannerUtils(unittest.TestCase):

    def test_generate_random_header_case(self):
        header = "Content-Type"
        random_case_header = generate_random_header_case(header)
        self.assertEqual(len(header), len(random_case_header), "Length should not change.")
        self.assertEqual(header.lower(), random_case_header.lower(), "Lowercase versions should match.")
        # Check if at least some variation occurs (not strictly guaranteed but highly likely)
        # self.assertNotEqual(header, random_case_header, "Header should have varied casing in most runs.")

    def test_generate_url_path_variation(self):
        base_path = "/test"
        variation = generate_url_path_variation(base_path)
        self.assertTrue(variation.startswith(base_path), "Variation should start with base_path.")
        # Further checks could ensure it's one of the expected variation types.

    

if __name__ == '__main__':
    unittest.main()
