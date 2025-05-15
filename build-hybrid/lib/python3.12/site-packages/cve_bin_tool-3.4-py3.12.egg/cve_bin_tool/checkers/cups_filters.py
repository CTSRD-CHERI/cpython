# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cups-filters

https://www.cvedetails.com/product/27229/Linuxfoundation-Cups-filters.html?vendor_id=11448

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CupsFiltersChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"cups-filters version ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("linuxfoundation", "cups-filters")]
