# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for wavpack

https://www.cvedetails.com/product/36196/Wavpack-Project-Wavpack.html?vendor_id=16200
https://www.cvedetails.com/product/43617/Wavpack-Wavpack.html?vendor_id=17637

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class WavpackChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\n(?:libwavpack|[wW]av)"]
    VENDOR_PRODUCT = [("wavpack", "wavpack"), ("wavpack_project", "wavpack")]
