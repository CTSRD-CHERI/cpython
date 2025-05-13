# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for OpenBLAS

https://www.cvedetails.com/version-list/26026/106485/1/Openblas-Project-Openblas.html

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class OpenblasChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"OpenBLAS ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [("openblas_project", "openblas")]
