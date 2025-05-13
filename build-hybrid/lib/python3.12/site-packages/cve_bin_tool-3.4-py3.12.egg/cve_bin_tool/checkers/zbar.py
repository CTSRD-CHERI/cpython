# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for zbar

https://www.cvedetails.com/product/160348/Zbar-Project-Zbar.html?vendor_id=32703

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ZbarChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"zbar[a-z\-\r\n]*([0-9]+\.[0-9]+(\.[0-9]+)?)",
        r"([0-9]+\.[0-9]+(\.[0-9]+)?)[A-Za-z=:<'/ \(\)\-\r\n]*zbar",
    ]
    VENDOR_PRODUCT = [("zbar_project", "zbar")]
