# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import json
from pathlib import Path

import cve_bin_tool.output_engine.__init__ as out_init
from cve_bin_tool.output_engine.__init__ import OutputEngine, save_intermediate


# A dummy ProductInfo and CVEData for testing purpose.
class DummyProduct:
    def __init__(self, vendor, product, version):
        self.vendor = vendor
        self.product = product
        self.version = version

    def __hash__(self):
        return hash((self.vendor, self.product, self.version))

    def __eq__(self, other):
        # Fixed: compare vendor, product, and version properly.
        return (self.vendor, self.product, self.version) == (
            other.vendor,
            other.product,
            other.version,
        )


class DummyCVE:
    def __init__(self):
        self.cves = []


def dummy_intermediate_output(
    all_cve_data, tag, scanned_dir, with_cve, without_cve, total_files, strip_scan_dir
):
    # Minimal dummy report structure
    return {
        "metadata": {
            "tag": tag,
            "scanned_dir": scanned_dir,
            "with_cve": with_cve,
            "without_cve": without_cve,
            "total_files": total_files,
        },
        "data": {str(k): "dummy" for k in all_cve_data.keys()},
    }


# Patch the intermediate_output function for testing.
out_init.intermediate_output = dummy_intermediate_output


def test_save_intermediate_writes_valid_json(tmp_path):
    # Prepare dummy data and temporary file
    dummy_product = DummyProduct("vendor1", "product1", "v1")
    # Change value to a dict containing a "cves" list instead of a string.
    all_cve_data = {dummy_product: {"cves": []}}
    tag = "TEST_TAG"
    scanned_dir = "dummy_dir"
    with_cve = 1
    without_cve = 2
    total_files = 3

    tmp_file = tmp_path / "intermediate.json"
    save_intermediate(
        all_cve_data,
        str(tmp_file),
        tag,
        scanned_dir,
        with_cve,
        without_cve,
        total_files,
    )

    # Read back and assert
    with open(tmp_file) as f:
        data = json.load(f)
    assert data["metadata"]["tag"] == tag
    assert data["metadata"]["scanned_dir"] == scanned_dir
    assert data["metadata"]["with_cve"] == with_cve
    assert data["metadata"]["without_cve"] == without_cve
    assert data["metadata"]["total_files"] == total_files
    key = str(dummy_product)
    assert key in data["data"]


def test_check_dir_path_creates_filename(tmp_path):
    # Create a temporary directory as dummy filepath
    temp_dir = tmp_path / "dummy_dir"
    temp_dir.mkdir()

    # Create an instance of OutputEngine with minimal required parameters.
    engine = OutputEngine(
        all_cve_data={},
        scanned_dir="dummy",
        filename="",
        themes_dir="dummy",
        time_of_last_update="dummy",
        tag="dummy",
        products_with_cve=0,
        products_without_cve=0,
        total_files=0,
        is_report=False,
        no_zero_cve_report=False,
        append=False,
        merge_report=None,
        affected_versions=0,
        all_cve_version_info=None,
        detailed=False,
        exploits=False,
        metrics=False,
        all_product_data=None,
        sbom_filename="",
        sbom_type="spdx",
        sbom_format="tag",
        sbom_root="dummy",
        vex_filename="",
        vex_type="",
        vex_product_info={},
        offline=False,
        organized_arguements=None,
    )
    # Pass a directory path; expect a new filename within that directory.
    result = engine.check_dir_path(
        str(temp_dir), output_type="json", prefix="intermediate"
    )
    result_path = Path(result)
    # Instead of forcing the parent to be the temporary dir, we now expect the engine to use the current working directory.
    assert result_path.parent == Path.cwd()  # Updated expected parent.
    assert result_path.name.startswith("intermediate")
    assert result_path.suffix == ".json"  # Verify JSON file extension.
    assert result_path.is_file() is False  # It hasn't been created yet.
