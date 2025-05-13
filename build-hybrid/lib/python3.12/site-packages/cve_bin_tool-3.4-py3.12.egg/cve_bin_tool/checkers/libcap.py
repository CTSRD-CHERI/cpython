# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for libcap

https://www.cvedetails.com/product/27074/Libcap-Libcap.html?vendor_id=13117
https://www.cvedetails.com/product/143145/Libcap-Project-Libcap.html?vendor_id=30906

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class LibcapChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"libcap-([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("libcap", "libcap"), ("libcap_project", "libcap")]
