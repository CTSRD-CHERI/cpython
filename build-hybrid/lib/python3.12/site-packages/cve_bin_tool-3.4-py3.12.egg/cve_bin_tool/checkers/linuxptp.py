# Copyright (C) 2024 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for linuxptp

https://www.cvedetails.com/product/98135/Linuxptp-Project-Linuxptp.html?vendor_id=24927

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LinuxptpChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"(?:ptp|PTP_)[A-Za-z0-9_:% \[\]\-\.\r\n]*\r?\n([0-9]\.[0-9])\r?\n"
    ]
    VENDOR_PRODUCT = [("linuxptp_project", "linuxptp")]
