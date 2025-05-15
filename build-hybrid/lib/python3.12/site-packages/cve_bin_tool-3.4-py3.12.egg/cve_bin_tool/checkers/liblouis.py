# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for liblouis

https://www.cvedetails.com/product/39891/Liblouis-Liblouis.html?vendor_id=16875

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LiblouisChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"liblouis[a-zA-Z0-9:%/'_=,@ \-\"\\\(\)\.\r\n]*\r?\n([0-9]+\.[0-9]+\.[0-9]+)"
    ]
    VENDOR_PRODUCT = [("liblouis", "liblouis")]
