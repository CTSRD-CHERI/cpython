# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
CVE-bin-tool file tests
"""

import pytest

from cve_bin_tool.async_utils import NamedTemporaryFile, aio_rmfile
from cve_bin_tool.file import aio_is_binary


class TestFile:
    """Tests the CVE Bin Tool file binary checker."""

    async def _write_magic_signature(self, f, signature):
        """Helper function to write a magic signature to a file."""
        await f.write(signature)
        await f.seek(0)

    async def _check_file_type(self, file_type, signature, expected_result):
        """Helper function to check if a file is binary based on its type."""
        async with NamedTemporaryFile("w+b", suffix=file_type, delete=False) as f:
            await self._write_magic_signature(f, signature)
            assert await aio_is_binary(f.name) == expected_result
        await aio_rmfile(f.name)

    @pytest.mark.asyncio
    async def _check_test(self, type):
        """Helper function to parse a binary file and check whether
        the given string is in the parsed result"""
        file_signatures = {
            "elf": (b"\x7f\x45\x4c\x46\x02\x01\x01\x03\n", True, ".out"),
            "mach_o_32": (b"\xFE\xED\xFA\xCE\x00\x00\x00\x00", True, ".out"),
            "mach_o_64": (b"\xFE\xED\xFA\xCF\x00\x00\x00\x00", True, ".out"),
            "mach_o_universal": (b"\xCA\xFE\xBA\xBE\x00\x00\x00\x00", True, ".out"),
            "ios_arm": (b"\xCF\xFA\xED\xFE\x00\x00\x00\x00", True, ".out"),
            "wasm": (b"\x00\x61\x73\x6D\x01\x00\x00\x00", True, ".out"),
            "c": (b"#include <stdio.h>", False, ".c"),
            "single_byte": (b"1", False, ".txt"),
            "windows": (b"MZ", True, ".txt"),
        }
        signature, expected_result, file_type = file_signatures.get(
            type, (b"some other data\n", False, ".txt")
        )
        await self._check_file_type(file_type, signature, expected_result)

    @pytest.mark.asyncio
    async def test_binary_elf_file(self):
        """file *.out"""
        await self._check_test("elf")

    @pytest.mark.asyncio
    async def test_binary_mach_o_32_file(self):
        """file *.out"""
        await self._check_test("mach_o_32")

    @pytest.mark.asyncio
    async def test_binary_mach_o_64_file(self):
        """file *.out"""
        await self._check_test("mach_o_64")

    @pytest.mark.asyncio
    async def test_binary_mach_o_universal_file(self):
        """file *.out"""
        await self._check_test("mach_o_universal")

    @pytest.mark.asyncio
    async def test_binary_ios_arm_file(self):
        """file *.out"""
        await self._check_test("ios_arm")

    @pytest.mark.asyncio
    async def test_binary_wasm_file(self):
        """file *.out"""
        await self._check_test("wasm")

    @pytest.mark.asyncio
    async def test_source_file(self):
        """file *.c"""
        await self._check_test("c")

    @pytest.mark.asyncio
    async def test_text_file(self):
        """file *.txt"""
        await self._check_test("other")

    @pytest.mark.asyncio
    async def test_single_byte_file(self):
        """file single-byte"""
        await self._check_test("single_byte")

    @pytest.mark.asyncio
    async def test_windows(self):
        """file *.txt"""
        await self._check_test("windows")
