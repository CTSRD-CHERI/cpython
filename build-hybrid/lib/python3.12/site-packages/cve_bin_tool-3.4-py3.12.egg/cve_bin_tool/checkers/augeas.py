# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for augeas

https://www.cvedetails.com/product/26487/Augeas-Augeas.html?vendor_id=12963

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class AugeasChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n/augeas"]
    VENDOR_PRODUCT = [("augeas", "augeas")]
