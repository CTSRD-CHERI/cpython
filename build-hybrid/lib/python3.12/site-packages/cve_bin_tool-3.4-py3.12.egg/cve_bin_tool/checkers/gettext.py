# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for gettext

https://www.cvedetails.com/product/4701/GNU-Gettext.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class GettextChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"gettext[A-Za-z:\-\r\n]*([0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("gnu", "gettext")]
