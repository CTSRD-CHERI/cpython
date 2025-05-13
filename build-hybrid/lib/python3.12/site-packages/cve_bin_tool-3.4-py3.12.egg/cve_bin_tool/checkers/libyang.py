# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libyang

https://www.cvedetails.com/product/75616/Cesnet-Libyang.html?vendor_id=22238

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibyangChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"libyang-([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-zA-Z0_%'= \-\(\)\[\]\.\r\n]*YANG",
    ]
    VENDOR_PRODUCT = [("cesnet", "libyang")]
