# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gsasl

https://www.cvedetails.com/product/122706/GNU-Gnu-Sasl.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GsaslChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9 \r\n]*SASLprep"]
    VENDOR_PRODUCT = [("gnu", "gnu_sasl")]
