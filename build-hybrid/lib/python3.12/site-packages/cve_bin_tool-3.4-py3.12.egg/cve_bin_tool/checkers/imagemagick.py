# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for ImageMagick

https://www.cvedetails.com/product/3034/

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class ImagemagickChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [r"ImageMagick ([0-9]+\.[0-9]+\.[0-9]+)"]
    VENDOR_PRODUCT = [
        ("imagemagick", "imagemagick"),
    ]
