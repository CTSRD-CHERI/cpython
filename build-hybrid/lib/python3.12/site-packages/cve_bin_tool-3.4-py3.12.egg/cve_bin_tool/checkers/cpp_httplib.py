# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cpp-httplib

https://www.cvedetails.com/product/83519/Cpp-httplib-Project-Cpp-httplib.html?vendor_id=23214

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CppHttplibChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"cpp-httplib/\r?\n([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("cpp-httplib_project", "cpp-httplib")]
