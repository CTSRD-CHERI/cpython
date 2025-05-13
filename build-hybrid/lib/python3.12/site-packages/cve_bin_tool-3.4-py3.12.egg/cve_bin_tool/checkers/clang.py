# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for clang

https://www.cvedetails.com/product/27514/Llvm-Clang.html?vendor_id=13260

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ClangChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Clang ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("llvm", "clang")]
