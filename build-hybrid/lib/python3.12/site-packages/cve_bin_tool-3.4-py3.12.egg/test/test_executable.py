# Copyright (C) 2024 Iain Coulter
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool version scanner file/is_binary tests
"""

from os import remove
from tempfile import NamedTemporaryFile

from cve_bin_tool.version_scanner import VersionScanner


class TestFile:
    """Tests the CVE Bin Tool file using 'file' command."""

    def _write_magic_signature(self, f, signature):
        """Helper function to write a magic signature to a file."""
        f.write(signature)
        f.seek(0)

    def _check_file_type(self, file_type, signature, expected_result):
        """Helper function to check if a file is binary based on its type."""
        with NamedTemporaryFile("w+b", suffix=file_type, delete=False) as f:
            self._write_magic_signature(f, signature)
            scanner = VersionScanner()
            result, *_ = scanner.is_executable(f.name)
            assert (
                result == expected_result
            ), f"Expected {expected_result}, but got {result}"
        remove(f.name)

    def _check_test(self, type):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        file_signatures = {
            "elf": (b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n", True, ".out"),
            "mach_o_32": (b"\xFE\xED\xFA\xCE\x00\x00\x00\x00", True, ".out"),
            "mach_o_64": (b"\xFE\xED\xFA\xCF\x00\x00\x00\x00", True, ".out"),
            "mach_o_universal": (b"\xCA\xFE\xBA\xBE\x00\x00\x00\x00", True, ".out"),
            "ios_arm": (b"\xCF\xFA\xED\xFE\x00\x00\x00\x00", True, ".out"),
            "wasm": (b"yoyo\x00\x61\x73\x6D\x01\x00\x00\x00", True, ".out"),
            "c": (b"#include <stdio.h>", False, ".c"),
            "single_byte": (b"1", False, ".txt"),
            "windows": (b"MZ\x90\x00", True, ".dll"),
        }
        signature, expected_result, file_type = file_signatures.get(
            type, (b"some other data\n", False, ".txt")
        )
        self._check_file_type(file_type, signature, expected_result)

    def test_binary_elf_file(self):
        """file *.out"""
        self._check_test("elf")

    def test_binary_mach_o_32_file(self):
        """file *.out"""
        self._check_test("mach_o_32")

    def test_binary_mach_o_64_file(self):
        """file *.out"""
        self._check_test("mach_o_64")

    def test_binary_mach_o_universal_file(self):
        """file *.out"""
        self._check_test("mach_o_universal")

    def test_binary_ios_arm_file(self):
        """file *.out"""
        self._check_test("ios_arm")

    def test_binary_wasm_file(self):
        """file *.out"""
        self._check_test("wasm")

    def test_source_file(self):
        """file *.c"""
        self._check_test("c")

    def test_single_byte_file(self):
        """file single-byte"""
        self._check_test("single_byte")

    def test_windows(self):
        """file *.txt"""
        self._check_test("windows")

    def test_other_file(self):
        """file *.txt"""
        self._check_test("other")
