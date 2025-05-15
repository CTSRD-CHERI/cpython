# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libreswan

https://www.cvedetails.com/product/26318/Libreswan-Libreswan.html?vendor_id=12913

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibreswanChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libreswan-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libreswan", "libreswan")]
