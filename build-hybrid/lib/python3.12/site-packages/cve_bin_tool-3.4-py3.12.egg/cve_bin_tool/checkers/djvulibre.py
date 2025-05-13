# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for djvulibre
"""
from cve_bin_tool.checkers import Checker


class DjvulibreChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTERNS = []
    VERSION_PATTERNS = [
        r"DjVuLibre-([0-9]+\.[0-9]+\.[0-9]+[a-z]*)",
    ]
    VENDOR_PRODUCT = [("djvulibre_project", "djvulibre")]
