# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for cairo

https://www.cvedetails.com/version-list/12652/24854/1/Cairographics-Cairo.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CairoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"/cairo-([0-9]+\.[0-9]+\.[0-9]+)/",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n[a-z\./]*(?:cairo|CAIRO)",
    ]
    VENDOR_PRODUCT = [
        ("cairographics", "cairo"),
    ]
