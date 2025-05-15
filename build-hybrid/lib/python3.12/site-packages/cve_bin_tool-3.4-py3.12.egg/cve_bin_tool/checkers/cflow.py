# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for cflow

https://www.cvedetails.com/product/59240/GNU-Cflow.html?vendor_id=72

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class CflowChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"GNU cflow ([0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("gnu", "cflow")]
