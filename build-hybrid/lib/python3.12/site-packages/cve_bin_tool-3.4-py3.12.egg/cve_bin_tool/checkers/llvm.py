# Copyright (C) 2025 Keysight Technologies
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE checker for LLVM
"""

from cve_bin_tool.checkers import Checker


class LlvmChecker(Checker):
    CONTAINS_PATTERNS = []
    FILENAME_PATTTERN = []
    VERSION_PATTERNS = [
        r"LLVM version ([0-9]+\.[0-9]+\.[0-9]+)",
        r"/llvm-[a-z]+/([0-9]+\.[0-9]+\.[0-9]+)",
    ]
    VENDOR_PRODUCT = [("llvm", "llvm")]
