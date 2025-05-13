# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from cve_bin_tool.output_engine.print_mode import html_print_mode


def test_html_print_mode_default():
    output = html_print_mode(
        all_cve_data={},
        all_cve_version_info=None,
        directory="dummy_dir",
        products_with_cve=0,
        products_without_cve=0,
        total_files=0,
        star_warn="",
        merge_report=None,
        version="0.1",
        full_html=False,
        affected_versions=0,
    )
    assert isinstance(output, str)
    # Expect output to be a snippet—not a complete HTML document
    assert "<html" not in output


def test_html_print_mode_full_html():
    output = html_print_mode(
        all_cve_data={},
        all_cve_version_info=None,
        directory="dummy_dir",
        products_with_cve=0,
        products_without_cve=0,
        total_files=0,
        star_warn="",
        merge_report=None,
        version="0.1",
        full_html=True,
        affected_versions=0,
    )
    assert isinstance(output, str)
    # For full_html case, expect typical HTML structural tags present
    assert "<html" in output or "DOCTYPE html" in output


def test_html_print_mode_with_data():
    # New test: use non-empty CVE data.
    dummy_data = {"dummy": {"cves": ["CVE-1234", "CVE-5678"]}}
    output = html_print_mode(
        all_cve_data=dummy_data,
        all_cve_version_info=None,
        directory="dummy_dir",
        products_with_cve=1,
        products_without_cve=0,
        total_files=1,
        star_warn="",
        merge_report=None,
        version="0.1",
        full_html=True,
        affected_versions=0,
    )
    assert "CVE-1234" in output or "dummy" in output
