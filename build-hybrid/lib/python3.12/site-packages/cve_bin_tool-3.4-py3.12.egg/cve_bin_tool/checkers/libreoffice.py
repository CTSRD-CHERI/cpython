# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libreoffice

https://www.cvedetails.com/product/21008/Libreoffice-Libreoffice.html?vendor_id=11439

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibreofficeChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libreoffice-([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("libreoffice", "libreoffice")]
