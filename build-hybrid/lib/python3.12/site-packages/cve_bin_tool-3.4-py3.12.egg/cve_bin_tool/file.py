# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

"""
To determine if a file is executable we read the first few bytes of a file and
check it against various signatures for different executable file formats.
"""
import inspect
import sys

from cve_bin_tool.async_utils import FileIO, run_coroutine


async def aio_is_binary(filename: str) -> bool:
    """Read the magic bytes from a file and determine if it is an executable
    binary."""
    try:
        signature: bytes = await read_signature(filename)
    except PermissionError:
        return False
    for name, method in inspect.getmembers(
        sys.modules[__name__], predicate=inspect.isfunction
    ):
        if name.startswith("check_"):
            if method(filename, signature):
                return True
    return False


def is_binary(filename: str) -> bool:
    """Determine if a file is an executable binary.

    Args:
        filename (str): The path to the file to check.

    Returns:
        bool: True if the file is an executable binary, False otherwise.
    """
    return run_coroutine(aio_is_binary(filename))


async def read_signature(filename: str, length: int = 4) -> bytes:
    """Read the signature, first length bytes, from filename."""
    async with FileIO(filename, "rb") as file_handle:
        return await file_handle.read(length)


def check_elf(_filename: str, signature: bytes) -> bool:
    """Check for an ELF signature."""
    return signature == b"\x7f\x45\x4c\x46"


def check_pe(_filename: str, signature: bytes) -> bool:
    """Check for windows/dos PE signature, aka 0x5a4d."""
    return signature[:4] == b"\x4d\x5a"


def check_fake_test(_filename: str, signature: bytes) -> bool:
    """check for fake tests under windows."""
    return signature == b"MZ\x90\x00"


def check_mach_o_32(_filename: str, signature: bytes) -> bool:
    """Check for Mach-O 32-bit signature."""
    return signature[:4] == b"\xFE\xED\xFA\xCE"


def check_mach_o_64(_filename: str, signature: bytes) -> bool:
    """Check for Mach-O 64-bit signature."""
    return signature[:4] == b"\xFE\xED\xFA\xCF"


def check_mach_o_universal(_filename: str, signature: bytes) -> bool:
    """Check for Mach-O Universal Binary signature."""
    return signature[:4] == b"\xCA\xFE\xBA\xBE"


def check_ios_arm(_filename: str, signature: bytes) -> bool:
    """Check for Mach-O Universal Binary signature."""
    return signature[:4] == b"\xCF\xFA\xED\xFE"


def check_wasm(_filename: str, signature: bytes) -> bool:
    """Check for WebAssembly (WASM) signature."""
    return signature[:4] == b"\x00\x61\x73\x6D"
