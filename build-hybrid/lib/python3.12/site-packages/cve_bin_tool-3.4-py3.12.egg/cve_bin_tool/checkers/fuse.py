# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for fuse

https://www.cvedetails.com/product/32028/Fuse-Project-Fuse.html?vendor_id=15522

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class FuseChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"(?:FUSE library|fusermount) version: %s\r?\n([0-9]+\.[0-9]+\.[0-9]+)",
        r"([0-9]+\.[0-9]+\.[0-9]+)\r?\n(?:FUSE library|fusermount) version",
    ]
    VENDOR_PRODUCT = [("fuse_project", "fuse")]
