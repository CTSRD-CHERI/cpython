# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json

from cve_bin_tool.parsers.javascript import JavascriptParser


# Dummy logger to suppress debug output
class DummyLogger:
    def debug(self, msg):
        pass


# Subclass to override vendor methods for testing
class DummyJavascriptParser(JavascriptParser):
    def __init__(self):
        super().__init__(cve_db=None, logger=DummyLogger())

    def get_vendor(self, purl, product, version):
        return ["vendor_dummy"]

    def find_vendor_from_purl(self, purl, version):
        return (["vendor_yarn"], True)

    def find_vendor(self, product, version):
        return ["vendor_yarn_alt"]


# Test for package-lock.json branch with lockfileVersion>=2
def test_process_package_lock_lockfile_v2(tmp_path):
    data = {
        "lockfileVersion": 2,
        "packages": {
            "": {"version": "1.0.0", "requires": {"dep1": "1.2.3", "dep2": "*"}},
            "node_modules/dep3": {"version": "2.3.4", "requires": {}},
        },
    }
    file_content = json.dumps(data)
    file_path = tmp_path / "package-lock.json"
    file_path.write_text(file_content)

    parser = DummyJavascriptParser()
    results = list(parser.run_checker(str(file_path)))
    # Expect vendor_dummy for:
    #  - package "" -> yields vendor_dummy
    #  - its require "dep1" yields vendor_dummy (skip if version=="*")
    #  - package "node_modules/dep3" yields vendor_dummy
    expected = ["vendor_dummy", "vendor_dummy", "vendor_dummy"]
    assert results == expected


# Test for yarn.lock branch matching regex pattern
def test_process_yarn_lock(tmp_path):
    yarn_content = """"somepackage@^1.0.0":
  version "1.0.0"
"anotherpkg@~2.0.0":
  version "2.0.0"
"""
    file_path = tmp_path / "yarn.lock"
    file_path.write_text(yarn_content)

    parser = DummyJavascriptParser()
    results = list(parser.run_checker(str(file_path)))
    # Two matches yield vendor from find_vendor_from_purl for each
    expected = ["vendor_yarn", "vendor_yarn"]
    assert results == expected
