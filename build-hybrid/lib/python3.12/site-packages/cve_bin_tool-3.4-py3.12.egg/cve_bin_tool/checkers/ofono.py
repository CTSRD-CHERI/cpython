# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for ofono

https://www.cvedetails.com/product/171650/Ofono-Project-Ofono.html?vendor_id=35263

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OfonoChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"OFONO_[0-9a-zA-Z:'%=+?,-_/!$*>^ \.\"\(\)\r\n]*\r?\n([0-9]+\.[0-9]+)\r?\n"
    ]
    VENDOR_PRODUCT = [("ofono_project", "ofono")]
