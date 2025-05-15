# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for xz

https://www.cvedetails.com/product/38995/Tukaani-XZ.html?vendor_id=16730

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class XzChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"xz \(XZ Utils\) ([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9,'_=:*&!? \-\.\[\]\"\(\)\r\n]*7zXZ[a-zA-z0-9\r\n]*   @@@",
    ]
    VENDOR_PRODUCT = [("tukaani", "xz")]
