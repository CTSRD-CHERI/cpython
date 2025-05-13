# Copyright (C) 2025 Orange
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of OpenWrt opkg .control files."""

from re import MULTILINE, compile, search

from cve_bin_tool.parsers import Parser
from cve_bin_tool.strings import parse_strings
from cve_bin_tool.util import ProductInfo, ScanInfo, decode_cpe22


class OpkgParser(Parser):
    """
    Parser for OpenWrt opkg .control files based on
    https://openwrt.org/docs/guide-user/additional-software/opkg
    """

    PARSER_MATCH_FILENAMES = [
        ".control",
    ]

    def __init__(self, cve_db, logger):
        """Initialize the opkg package metadata parser."""
        super().__init__(cve_db, logger)

    def run_checker(self, filename):
        """
        This generator runs only for opkg packages.
        There are no actual checkers.
        """
        self.filename = filename
        lines = parse_strings(self.filename)
        try:
            # product and vendor are extracted from CPE-ID
            # Wrong results will be raised if Package name is used
            # (e.g., libsqlite3-0 instead of sqlite, libopenssl3 instead of openssl)
            # or if vendor is omitted (e.g., cloudflare:zlib is different from gnu:zlib)
            cpe_id = search(compile(r"^CPE-ID: (.+)$", MULTILINE), lines)
            if cpe_id is None:
                self.logger.debug(f"{filename} doesn't contain any CPE-ID")
                return
            # version is always suffixed by a digit (e.g. 2.90-1 instead of 2.90)
            version = search(
                compile(r"^Version: (.+)-([0-9\.]+)$", MULTILINE), lines
            ).group(1)
            vendor, product, _ = decode_cpe22(f"{cpe_id.group(1)}:{version}")
            vendorlist: list[ScanInfo] = [
                ScanInfo(ProductInfo(vendor, product, version), self.filename)
            ]
            yield from vendorlist

        except AttributeError:
            self.logger.debug(f"{filename} is an invalid OpenWrt opkg .control file")
        self.logger.debug(f"Done scanning file: {filename}")
