# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for oath_toolkit

https://www.cvedetails.com/product/27196/Nongnu-Oath-Toolkit.html?vendor_id=6788

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OathToolkitChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+)[0-9A-Za-z/%\-\*\.\:\t\r\n]*Liboath"]
    VENDOR_PRODUCT = [("nongnu", "oath_toolkit")]
