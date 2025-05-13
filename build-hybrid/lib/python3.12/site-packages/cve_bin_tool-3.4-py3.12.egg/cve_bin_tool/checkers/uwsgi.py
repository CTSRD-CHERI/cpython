# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for uwsgi

https://www.cvedetails.com/product/43616/Unbit-Uwsgi.html?vendor_id=17636

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class UwsgiChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[a-z_ \r\n]*uwsgi",
        r"uwsgi[a-z_/% \(\)\r\n]*([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("unbit", "uwsgi")]
