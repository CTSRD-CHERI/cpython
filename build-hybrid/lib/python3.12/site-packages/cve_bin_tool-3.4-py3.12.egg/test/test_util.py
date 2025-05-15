# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool util tests
"""
import inspect
from typing import DefaultDict

from cve_bin_tool.cve_scanner import CVEScanner
from cve_bin_tool.util import CVEData, ProductInfo, inpath


class TestUtil:
    """Test the util functions"""

    def test_inpath(self):
        """Test the check to see if a command line utility is installed
        and in path before we try to run it."""
        assert inpath("python")

    def test_not_inpath(self):
        assert not inpath("cve_bin_tool_test_for_not_in_path")


class TestSignature:
    """Tests signature of critical class and functions"""

    def test_cve_scanner(self):
        sig = inspect.signature(CVEScanner.get_cves)
        expected_args = {"product_info", "triage_data", "self"}
        assert (
            set(sig.parameters) - expected_args == set()
        ), "Parameters of get_cves has been changed. Make sure it isn't breaking InputEngine!"

        instance_attrs = vars(CVEScanner)["__annotations__"]
        assert (
            instance_attrs["all_cve_data"] == DefaultDict[ProductInfo, CVEData]
        ), "Type of all_cve_data has been changed. Make sure it isn't breaking OutputEngine!"


class TestProductInfo:
    """Tests the ProductInfo class and functions"""

    def test_product_info_with_purl(self):
        vendor = "vendor_name"
        product = "product_name"
        version = "1.0.0"
        purl = "pkg:type/namespace/product@version"

        product_info = ProductInfo(
            vendor=vendor,
            product=product,
            version=version,
            purl=purl,
        )

        assert product_info.vendor == vendor
        assert product_info.product == product
        assert product_info.version == version
        assert product_info.purl == purl

    def test_product_info_without_purl(self):
        vendor = "vendor_name"
        product = "product_name"
        version = "1.0.0"

        product_info = ProductInfo(vendor=vendor, product=product, version=version)

        assert product_info.vendor == vendor
        assert product_info.product == product
        assert product_info.version == version
        assert product_info.purl is None

    def test_product_info_equality(self):
        vendor = "vendor_name"
        product = "product_name"
        version = "1.0.0"
        purl = "pkg:type/namespace/product@version"

        product_info_1 = ProductInfo(
            vendor=vendor,
            product=product,
            version=version,
            purl=purl,
        )
        product_info_2 = ProductInfo(vendor=vendor, product=product, version=version)

        assert (
            product_info_1 == product_info_2
        )  # Should be equal based on vendor, product, version

    def test_product_info_hashing(self):
        vendor = "vendor_name"
        product = "product_name"
        version = "1.0.0"
        purl = "pkg:type/namespace/product@version"

        product_info_1 = ProductInfo(
            vendor=vendor,
            product=product,
            version=version,
            purl=purl,
        )
        product_info_2 = ProductInfo(vendor=vendor, product=product, version=version)

        assert hash(product_info_1) == hash(product_info_2)  # Hashes should be the same
