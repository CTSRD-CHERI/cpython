# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for toybox

https://www.cvedetails.com/product/117980/Toybox-Project-Toybox.html?vendor_id=27827

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ToyboxChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"toybox[A-Za-z0-9_%>/ \-\.\r\n]*([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("toybox_project", "toybox")]
