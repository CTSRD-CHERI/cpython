# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later
"""Python script containing all functionalities related to parsing of C/C++ conan.lock files."""

import json
import re

from cve_bin_tool.parsers import Parser


class CCppParser(Parser):
    """
    Parser for C/C++ conan.lock files based on
    https://docs.conan.io/2/tutorial/versioning/lockfiles.html
    """

    PARSER_MATCH_FILENAMES = [
        "conan.lock",
    ]

    def __init__(self, cve_db, logger):
        super().__init__(cve_db, logger)
        self.purl_pkg_type = "conan"

    def generate_purl(self, product, vendor="", version="", qualifier={}, subpath=None):
        """Generates PURL after normalizing all components."""
        product = re.sub(r"[^a-zA-Z0-9._-]", "", product).lower()

        if not product:
            return None

        purl = super().generate_purl(
            product,
            vendor,
            version,
            qualifier,
            subpath,
        )

        return purl

    def run_checker(self, filename):
        """Parse the file and yield valid PURLs."""
        self.filename = filename
        with open(self.filename) as fh:
            data = json.load(fh)
            requires = data["requires"]
            build_requires = data["build_requires"]
            if requires:
                for require in requires:
                    product = require.split("#")[0].split("/")[0]
                    version = require.split("#")[0].split("/")[1]
                    purl = self.generate_purl(product)
                    vendor = self.get_vendor(purl, product, version)
                    if vendor is not None:
                        yield from vendor
            if build_requires:
                for build_require in build_requires:
                    product = build_require.split("#")[0].split("/")[0]
                    version = build_require.split("#")[0].split("/")[1]
                    purl = self.generate_purl(product)
                    vendor = self.get_vendor(purl, product, version)
                    if vendor is not None:
                        yield from vendor
        self.logger.debug(f"Done scanning file: {self.filename}")
