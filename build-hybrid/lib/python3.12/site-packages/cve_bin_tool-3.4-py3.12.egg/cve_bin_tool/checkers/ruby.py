# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ruby

https://www.cvedetails.com/product/12215/Ruby-lang-Ruby.html?vendor_id=7252

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RubyChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ruby ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("ruby-lang", "ruby")]
