# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for orc

https://www.cvedetails.com/product/170918/Gstreamer-ORC.html?vendor_id=9481

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OrcChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"Orc Compiler ([0-9]+\.[0-9]+\.[0-9]+)",
        r"orc-([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("gstreamer", "orc")]
