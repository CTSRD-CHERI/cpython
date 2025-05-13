# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import re
from unittest.mock import Mock

import plotly.graph_objects as go
import pytest
from playwright.sync_api import Locator, Page, expect

from cve_bin_tool.merge import MergeReports
from cve_bin_tool.output_engine.html import (
    get_intermediate_label,
    load_timeline_from_merged,
)
from cve_bin_tool.util import CVE, CVEData, ProductInfo, Remarks

from .pages.html_report import HTMLReport


class TestOutputHTML:
    MOCK_OUTPUT = {
        ProductInfo("vendor0", "product0", "1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1000",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    remarks=Remarks.NewFound,
                    comments="showup",
                ),
                CVE(
                    "CVE-1234-1001",
                    "LOW",
                    score=1.2,
                    cvss_version=2,
                    cvss_vector="CVSS2.0/C:H",
                    remarks=Remarks.NewFound,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product0", "2.8.6"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1002",
                    "LOW",
                    score=2.5,
                    cvss_version=3,
                    cvss_vector="CVSS3.0/C:H/I:L/A:M",
                    remarks=Remarks.Confirmed,
                    comments="",
                    metric={"EPSS": (0.1234, 0.5678)},
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "3.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1003",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.Mitigated,
                    comments="",
                    metric={"Foo": (0.4321, 0.8765)},
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product1", "4.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1004",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.Unexplored,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo("vendor1", "product2", "5.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1005",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.FalsePositive,
                    comments="",
                ),
            ],
            paths={""},
        ),
        ProductInfo("UNKNOWN", "product3", "6.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1006",
                    "HIGH",
                    score=7.5,
                    cvss_version=2,
                    cvss_vector="C:H/I:L/A:M",
                    remarks=Remarks.NotAffected,
                    comments="",
                )
            ],
            paths={""},
        ),
        ProductInfo("vendor0", "product4", "1.0", "usr/local/bin/product"): CVEData(
            cves=[
                CVE(
                    "UNKNOWN",
                    "MEDIUM",
                    score=4.2,
                    cvss_version=2,
                    cvss_vector="C:H",
                    remarks=Remarks.NewFound,
                    comments="showup",
                )
            ],
            paths={""},
        ),
        ProductInfo("wildcard*", "product5", "7.2.1.0"): CVEData(
            cves=[
                CVE(
                    "CVE-1234-1007",
                    "CRITICAL",
                    score=9.8,
                    cvss_version=3.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    remarks=Remarks.Confirmed,
                    comments="",
                )
            ],
            paths={""},
        ),
    }

    @pytest.fixture(autouse=True)
    def setup_method(self, page: Page) -> None:
        """Setup method for HTML Testing."""

        self.page = page
        self.html_report_page = HTMLReport(page, self.MOCK_OUTPUT)
        self.html_report_page.load()

    def teardown_method(self) -> None:
        """Teardown method for HTML Testing."""

        if hasattr(self, "html_report_page") and self.html_report_page is not None:
            self.html_report_page.cleanup()

    def check_products_visible_hidden(
        self, visible_row: Locator, *hidden_rows: Locator
    ) -> None:
        """Checks that the specified rows are visible or hidden."""

        for i in range(visible_row.count()):
            expect(visible_row.nth(i)).to_be_visible()

        for hidden_row in hidden_rows:
            for i in range(hidden_row.count()):
                expect(hidden_row.nth(i)).to_be_hidden()

    def test_interactive_mode_print_mode_switching(self) -> None:
        """Test Interactive mode to hide and Print mode to be visible when clicked on "Print Mode Button"
        Expect Interactive mode to be visible and Print mode to hide when clicked on "Interactive Mode Button"
        """

        print_mode_button = self.html_report_page.print_mode_button
        print_mode_page = self.html_report_page.print_mode_page
        interactive_mode_button = self.html_report_page.interactive_mode_button
        interactive_mode_page = self.html_report_page.interactive_mode_page

        print_mode_button.click()
        expect(print_mode_page).to_be_visible()
        expect(interactive_mode_page).to_be_hidden()
        expect(print_mode_page).to_contain_text("showup")

        interactive_mode_button.click()
        expect(interactive_mode_page).to_be_visible()
        expect(print_mode_page).to_be_hidden()

    def test_modal_switching(self) -> None:
        """Test modal to be visible when clicked on the product row or the vendor_product pill
        and to be hidden when clicked on the close button"""

        modal_content = self.html_report_page.modal_content.nth(0)
        product_row = self.html_report_page.product_rows.nth(0)
        modal_close_button = self.html_report_page.modal_close_button.nth(0)
        vendor_product_pill = self.html_report_page.vendor_product_pill.nth(0)

        expect(modal_content).to_be_hidden()
        product_row.click()
        expect(modal_content).to_be_visible()
        modal_close_button.click()
        expect(modal_content).to_be_hidden(timeout=10000)

        vendor_product_pill.click()
        expect(modal_content).to_be_visible()
        expect(modal_content).to_contain_text("Comment: showup")
        modal_close_button.click()
        expect(modal_content).to_be_hidden(timeout=10000)

    def test_product_search(self) -> None:
        """Test Search function to filter the products"""

        product_rows = self.html_report_page.product_rows

        for i in range(product_rows.count()):
            expect(product_rows.nth(i)).to_be_visible()

        expect(product_rows).to_have_count(8)
        self.html_report_page.search_product("product0")

        filtered_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0", flags=re.DOTALL)
        )
        unfiltered_row = product_rows.filter(has_text=re.compile(r"vendor1|product1"))
        self.check_products_visible_hidden(filtered_row, unfiltered_row)

    def test_product_remark_filter(self) -> None:
        """Test CVE product remark filters"""

        product_rows = self.html_report_page.product_rows

        new_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0.*NEW.*1.0", flags=re.DOTALL)
        )
        confirmed_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor0.*product0.*2.8.6", flags=re.DOTALL)
        )
        mitigated_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product1.*3.2.1.0", flags=re.DOTALL)
        )
        unexplored_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product1.*4.2.1.0", flags=re.DOTALL)
        )
        false_positive_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product2.*5.2.1.0", flags=re.DOTALL)
        )
        not_affected_cve_product_row = product_rows.filter(
            has_text=re.compile(r"vendor1.*product3.*6.2.1.0", flags=re.DOTALL)
        )

        new_cve_filter_button = self.html_report_page.new_cve_filter_button
        confirmed_cve_filter_button = self.html_report_page.confirmed_cve_filter_button
        mitigated_cve_filter_button = self.html_report_page.mitigated_cve_filter_button
        unexplored_cve_filter_button = (
            self.html_report_page.unexplored_cve_filter_button
        )
        false_positive_cve_filter_button = (
            self.html_report_page.false_positive_cve_filter_button
        )
        not_affected_cve_filter_button = (
            self.html_report_page.not_affected_cve_filter_button
        )

        new_cve_filter_button.click()
        self.check_products_visible_hidden(
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        confirmed_cve_filter_button.click()
        self.check_products_visible_hidden(
            confirmed_cve_product_row,
            new_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        mitigated_cve_filter_button.click()
        self.check_products_visible_hidden(
            mitigated_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        unexplored_cve_filter_button.click()
        self.check_products_visible_hidden(
            unexplored_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            false_positive_cve_product_row,
            not_affected_cve_product_row,
        )
        false_positive_cve_filter_button.click()
        self.check_products_visible_hidden(
            false_positive_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            not_affected_cve_product_row,
        )
        not_affected_cve_filter_button.click()
        self.check_products_visible_hidden(
            not_affected_cve_product_row,
            new_cve_product_row,
            confirmed_cve_product_row,
            mitigated_cve_product_row,
            unexplored_cve_product_row,
            false_positive_cve_product_row,
        )

    def test_cve_summary_table(self) -> None:
        """Test CVE Summary Table"""

        cve_summary_table = self.html_report_page.cve_summary_table
        expect(cve_summary_table).to_contain_text(["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_cve_remarks_table(self) -> None:
        """Test CVE Remarks Table"""

        cve_remarks_table = self.html_report_page.cve_remarks_table
        expect(cve_remarks_table).to_contain_text(
            [
                "NEW",
                "CONFIRMED",
                "MITIGATED",
                "UNEXPLORED",
                "FALSE POSITIVE",
                "NOT AFFECTED",
            ]
        )

    def test_without_intermediate_report(self) -> None:
        """Test that the HTML report renders correctly without an intermediate report."""

        # Clean up the previous page so intermediate report is not present
        if hasattr(self, "html_report_page") and self.html_report_page is not None:
            self.html_report_page.cleanup()

        self.html_report_page = HTMLReport(
            self.html_report_page.page, self.MOCK_OUTPUT, False
        )
        self.html_report_page.load()
        product_rows = self.html_report_page.product_rows

        # This test can be improved once the HTML report has unique ids
        expect(product_rows).to_have_count(8)

    def test_empty_cve_list(self) -> None:
        """Test that the HTML report renders correctly with an empty cve_data["cves"] list."""

        empty_output = {
            ProductInfo("vendor0", "product0", "1.0", "usr/local/bin/product"): CVEData(
                cves=[], paths={""}
            )
        }
        if hasattr(self, "html_report_page") and self.html_report_page is not None:
            self.html_report_page.cleanup()  # Clean up the previous page
        self.html_report_page = HTMLReport(self.page, empty_output)
        self.html_report_page.load()
        product_rows = self.html_report_page.product_rows

        expect(product_rows).to_have_count(0)


def test_get_intermediate_label_with_tag():
    """Test get_intermediate_label returns correct format with tag"""

    metadata = {"timestamp": "2025-03-04.12-00-00", "tag": "test-tag"}
    expected_label = "04 Mar 12:00-test-tag"
    assert get_intermediate_label(metadata) == expected_label


def test_get_intermediate_label_without_tag():
    """Test get_intermediate_label returns correct format without tag"""

    metadata = {"timestamp": "2025-03-04.12-00-00", "tag": ""}
    expected_label = "04 Mar 12:00"
    assert get_intermediate_label(metadata) == expected_label


def test_load_timeline_from_merged():
    """Test load_timeline_from_merged returns correct figures"""

    # Mock the MergeReports class
    mock_merge_report = Mock(spec=MergeReports)
    mock_merge_report.intermediate_cve_data = [
        {
            "metadata": {
                "products_with_cve": 5,
                "products_without_cve": 10,
                "total_files": 15,
                "severity": {
                    "CRITICAL": 1,
                    "HIGH": 2,
                    "MEDIUM": 3,
                    "LOW": 4,
                    "UNKNOWN": 0,
                },
                "timestamp": "2025-03-04.12-00-00",
                "tag": "test-tag",
            }
        },
        {
            "metadata": {
                "products_with_cve": 3,
                "products_without_cve": 7,
                "total_files": 10,
                "severity": {
                    "CRITICAL": 0,
                    "HIGH": 1,
                    "MEDIUM": 2,
                    "LOW": 3,
                    "UNKNOWN": 0,
                },
                "timestamp": "2025-03-03.12-00-00",
                "tag": "",
            }
        },
    ]
    mock_merge_report.get_intermediate_cve_scanner.return_value = [
        Mock(
            all_cve_data={
                ProductInfo(
                    product="product1", vendor="vendor1", version="1.0"
                ): CVEData(cves=[("CVE-1234-1000", "HIGH")]),
                ProductInfo(
                    product="product2", vendor="vendor2", version="2.0"
                ): CVEData(cves=[("CVE-1234-1001", "LOW")]),
                ProductInfo(
                    product="product3", vendor="vendor3", version="3.0"
                ): CVEData(cves=[]),
            }
        ),
        Mock(
            all_cve_data={
                ProductInfo(
                    product="product3", vendor="vendor3", version="3.0"
                ): CVEData(cves=[("CVE-1234-1002", "MEDIUM")]),
                ProductInfo(
                    product="product4", vendor="vendor4", version="4.0"
                ): CVEData(cves=[("CVE-1234-1003", "CRITICAL")]),
            }
        ),
    ]
    mock_merge_report.score = 0

    products_trace, total_files_trace, intermediate_timeline, severity_trace = (
        load_timeline_from_merged(mock_merge_report)
    )

    # Check if the returned objects are of the correct type
    assert isinstance(products_trace, go.Figure)
    assert isinstance(total_files_trace, go.Figure)
    assert isinstance(intermediate_timeline, go.Figure)
    assert isinstance(severity_trace, go.Figure)

    # Check if products_trace data in the figure is correct
    assert products_trace.data[0].name == "Products with CVE"
    assert products_trace.data[1].name == "Products without CVE"
    assert products_trace.data[0].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["products_with_cve"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["products_with_cve"],
    )
    assert products_trace.data[1].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["products_without_cve"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["products_without_cve"],
    )

    # Check if total_files trace data in the figure is correct
    assert total_files_trace.data[0].name == "Total Files"
    assert total_files_trace.data[0].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["total_files"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["total_files"],
    )

    # Check if severity_trace data in the figures is correct
    assert severity_trace.data[0].name == "CRITICAL"
    assert severity_trace.data[0].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["severity"]["CRITICAL"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["severity"]["CRITICAL"],
    )
    assert severity_trace.data[1].name == "HIGH"
    assert severity_trace.data[1].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["severity"]["HIGH"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["severity"]["HIGH"],
    )
    assert severity_trace.data[2].name == "MEDIUM"
    assert severity_trace.data[2].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["severity"]["MEDIUM"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["severity"]["MEDIUM"],
    )
    assert severity_trace.data[3].name == "LOW"
    assert severity_trace.data[3].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["severity"]["LOW"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["severity"]["LOW"],
    )
    assert severity_trace.data[4].name == "UNKNOWN"
    assert severity_trace.data[4].y == (
        mock_merge_report.intermediate_cve_data[1]["metadata"]["severity"]["UNKNOWN"],
        mock_merge_report.intermediate_cve_data[0]["metadata"]["severity"]["UNKNOWN"],
    )

    # Sort intermediate_timeline data by name to ensure consistent order
    intermediate_timeline_data_sorted = sorted(
        intermediate_timeline.data, key=lambda x: x.name
    )

    # Check if the intermediate_timeline contains the correct product data
    assert intermediate_timeline_data_sorted[0].name == "product1(1.0)"
    assert intermediate_timeline_data_sorted[0].y == (1, 0)
    assert intermediate_timeline_data_sorted[1].name == "product2(2.0)"
    assert intermediate_timeline_data_sorted[1].y == (1, 0)
    assert intermediate_timeline_data_sorted[2].name == "product3(3.0)"
    assert intermediate_timeline_data_sorted[2].y == (0, 1)
    assert intermediate_timeline_data_sorted[3].name == "product4(4.0)"
    assert intermediate_timeline_data_sorted[3].y == (0, 1)
