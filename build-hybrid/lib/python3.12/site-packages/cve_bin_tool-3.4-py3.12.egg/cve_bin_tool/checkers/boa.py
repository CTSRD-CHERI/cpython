# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for boa

https://www.cvedetails.com/product/18647/BOA-BOA.html?vendor_id=596

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class BoaChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Boa/([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("boa", "boa")]
