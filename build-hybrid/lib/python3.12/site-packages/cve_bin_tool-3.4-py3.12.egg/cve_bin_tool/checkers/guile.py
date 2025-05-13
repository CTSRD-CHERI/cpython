# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for guile

https://www.cvedetails.com/product/35586/

"""
from cve_bin_tool.checkers import Checker


class GuileChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = []
    VERSION_PATTERNS = [
        r"guileversion\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\n",
    ]
    VENDOR_PRODUCT = [("gnu", "guile")]
