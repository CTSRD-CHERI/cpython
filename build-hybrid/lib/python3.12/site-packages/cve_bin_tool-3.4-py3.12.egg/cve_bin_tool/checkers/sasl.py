# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for Cyrus SASL
References:
https://www.cvedetails.com/vulnerability-list/vendor_id-1321/product_id-2309/Cyrus-Sasl.html
"""
from cve_bin_tool.checkers import Checker


class SaslChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = []
    VERSION_PATTERNS = [
        r"Cyrus SASL\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\n",
    ]
    VENDOR_PRODUCT = [
        ("cyrus", "sasl"),
        ("cyrusimap", "cyrus-sasl"),
        ("cyrusimap", "cyrus_sasl"),
        ("carnegie_mellon_university", "cyrus-sasl"),
        ("cmu", "cyrus-sasl"),
    ]
