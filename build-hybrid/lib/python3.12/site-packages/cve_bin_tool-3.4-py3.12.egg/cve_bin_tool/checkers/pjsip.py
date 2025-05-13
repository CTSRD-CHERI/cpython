# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for pjsip

https://www.cvedetails.com/product/44396/Teluu-Pjsip.html?vendor_id=17771
https://www.cvedetails.com/product/65638/Pjsip-Pjsip.html?vendor_id=21360

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class PjsipChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"PJ_[A-Z0-9_:% ]*[d)]\r?\n([0-9]+\.[0-9]+(\.[0-9]+)?)"]
    VENDOR_PRODUCT = [("pjsip", "pjsip"), ("teluu", "pjsip")]
