# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for indent

https://www.cvedetails.com/product/157667/GNU-Indent.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class IndentChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"GNU indent[a-zA-Z0-9_%/+:`' \"\(\)\-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("gnu", "indent")]
