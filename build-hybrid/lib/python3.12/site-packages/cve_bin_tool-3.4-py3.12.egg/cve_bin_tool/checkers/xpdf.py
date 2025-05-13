# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for xpdf

https://www.cvedetails.com/product/60729/Glyphandcog-Xpdf.html?vendor_id=19912
https://www.cvedetails.com/product/55299/Glyphandcog-Xpdfreader.html?vendor_id=19912
https://www.cvedetails.com/product/43745/Xpdfreader-Xpdf.html?vendor_id=17664
https://www.cvedetails.com/product/118819/Xpdf-Project-Xpdf.html?vendor_id=28048

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class XpdfChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"Xpdf[a-zA-Z0-9:* \-\r\n]*([0-9]+\.[0-9]+)\r?\n"]
    VENDOR_PRODUCT = [
        ("glyphandcog", "xpdf"),
        ("glyphandcog", "xpdfreader"),
        ("xpdfreader", "xpdf"),
        ("xpdf_project", "xpdf"),
    ]
