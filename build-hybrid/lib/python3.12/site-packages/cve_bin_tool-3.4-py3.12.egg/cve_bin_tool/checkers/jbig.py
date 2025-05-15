# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for JBIG-KIT

https://www.cvedetails.com/version-list/13227/27412/1/Cambridge-Enterprise-Jbig-kit.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class JbigChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"JBIG-KIT ([0-9]+\.[0-9]) --",
    ]
    VENDOR_PRODUCT = [("cambridge_enterprise", "jbig-kit")]
