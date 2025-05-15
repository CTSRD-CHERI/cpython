# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for apr

https://www.cvedetails.com/product/17804/Apache-Portable-Runtime.html?vendor_id=45

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AprChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"apr_initialize\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n/tmp/apr",
    ]
    VENDOR_PRODUCT = [("apache", "portable_runtime")]
