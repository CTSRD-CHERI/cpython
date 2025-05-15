# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.output_engine.html import load_timeline_from_merged


# Dummy classes to mimic MergeReports and CVE Scanner
class DummyProduct:
    def __init__(self, product, version):
        self.product = product
        self.version = version


class DummyCVEScanner:
    def __init__(self):
        # Provide non-empty CVE list so the product is added
        self.all_cve_data = {
            DummyProduct("Dummy", "1.0"): {"cves": [("dummy", "KNOWN")]}
        }


# Dummy merge report to mimic the MergeReports interface
class DummyMergeReports:
    def __init__(self, intermediate_cve_data, score=0):
        self.intermediate_cve_data = intermediate_cve_data
        self.score = score

    def get_intermediate_cve_scanner(self, data, score):
        return [DummyCVEScanner()]


def test_load_timeline_from_merged_valid():
    # Create dummy merged reports with timestamps in "YYYY-MM-DD.HH-MM-SS" format.
    report1 = {
        "metadata": {
            "timestamp": "2024-07-16.12-00-00",
            "tag": "Report1",
            "products_with_cve": 1,
            "products_without_cve": 0,
            "total_files": 1,
            "severity": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        }
    }
    report2 = {
        "metadata": {
            "timestamp": "2024-07-16.13-00-00",
            "tag": "Report2",
            "products_with_cve": 2,
            "products_without_cve": 1,
            "total_files": 3,
            "severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0},
        }
    }
    dummy_merge = DummyMergeReports([report1, report2])
    # load_timeline_from_merged returns a tuple of (products_trace, total_files_trace, intermediate_timeline, severity_trace)
    _, _, intermediate_timeline, _ = load_timeline_from_merged(dummy_merge)
    # Expected order: Latest timestamp comes first.
    expected_label1 = "16 Jul 13:00-Report2"  # now first
    expected_label2 = "16 Jul 12:00-Report1"
    # Ensure at least one trace was added
    assert len(intermediate_timeline.data) > 0, "No trace added to timeline"
    x_values = intermediate_timeline.data[0].x
    assert expected_label1 in x_values
    assert expected_label2 in x_values
    # Assert that the first expected label comes before the second.
    assert x_values.index(expected_label1) < x_values.index(expected_label2)


def test_load_timeline_from_merged_empty():
    # When an empty dummy merge report is provided, each trace's x-values should be empty.
    dummy_merge = DummyMergeReports([])
    _, _, intermediate_timeline, _ = load_timeline_from_merged(dummy_merge)
    for trace in intermediate_timeline.data:
        # assert that no x-values are present
        assert len(trace.x) == 0


# ...additional tests for other small edge cases yet to be added...
