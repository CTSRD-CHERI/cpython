# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for dlt-daemon

https://www.cvedetails.com/product/136117/Covesa-Dlt-daemon.html?vendor_id=29885

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class DltDaemonChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"\r?\n([0-9]+\.[0-9]+\.[0-9]+)\r?\n[A-Za-z0-9+_:%(), \[\]\.\-\r\n]*DLT(?:_| Package Version)"
    ]
    VENDOR_PRODUCT = [("covesa", "dlt-daemon")]
