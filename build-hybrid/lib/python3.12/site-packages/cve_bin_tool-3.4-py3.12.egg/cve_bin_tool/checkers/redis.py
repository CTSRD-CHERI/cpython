# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later


"""
CVE checker for redis

https://www.cvedetails.com/product/101460/Redis-Redis.html?vendor_id=25596
https://www.cvedetails.com/product/47087/Redislabs-Redis.html?vendor_id=18560

"""
from __future__ import annotations

from cve_bin_tool.checkers import Checker


class RedisChecker(Checker):
    CONTAINS_PATTERNS: list[str] = []
    FILENAME_PATTERNS: list[str] = []
    VERSION_PATTERNS = [
        r"([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9%#:_/ \.\-\r\n]*redis(?:_version|\.pid)"
    ]
    VENDOR_PRODUCT = [("redis", "redis"), ("redislabs", "redis")]
