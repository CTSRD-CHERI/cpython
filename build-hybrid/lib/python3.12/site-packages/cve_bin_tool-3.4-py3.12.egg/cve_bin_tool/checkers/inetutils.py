# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for inetutils

https://www.cvedetails.com/product/4157/GNU-Inetutils.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class InetutilsChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nGNU inetutils"]
    VENDOR_PRODUCT = [("gnu", "inetutils")]
