# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for lzo2

https://www.cvedetails.com/version-list/21312/64331/1/Oberhumer-Lzo2.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class Lzo2Checker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"-[A-Za-z]{3} [0-9]{2} [0-9]{4}\r?\n([0-9]+\.[0-9]+)\r?\n"]
    VENDOR_PRODUCT = [("oberhumer", "lzo2")]
