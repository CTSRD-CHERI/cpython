# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for openvswitch

https://www.cvedetails.com/product/22779/Openvswitch-Openvswitch.html?vendor_id=12098

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenvswitchChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"openvswitch ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openvswitch", "openvswitch")]
