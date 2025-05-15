# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for firejail

https://www.cvedetails.com/product/36171/Firejail-Project-Firejail.html?vendor_id=16191

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FirejailChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)\r?\nfirejail version"]
    VENDOR_PRODUCT = [("firejail_project", "firejail")]
