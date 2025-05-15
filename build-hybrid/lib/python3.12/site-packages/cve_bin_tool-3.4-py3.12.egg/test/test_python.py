# Copyright (C) 2025 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess

from cve_bin_tool.parsers.python import PythonParser, PythonRequirementsParser


# Dummy logger to capture messages
class DummyLogger:
    def __init__(self):
        self.errors = []
        self.debugs = []

    def error(self, msg):
        self.errors.append(msg)

    def debug(self, msg):
        self.debugs.append(msg)


# Test for PythonRequirementsParser exception handling (CalledProcessError branch)
def test_requirements_parser_called_process_error(tmp_path, monkeypatch):
    # Create dummy requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("dummy==1.0.0")

    logger = DummyLogger()

    # Simulate subprocess.check_output:
    # - First call (pip install) raises CalledProcessError.
    # - Second call (pip --version) returns a version below 22.2.
    def fake_check_output(args, stderr=None):
        if args[0] == "pip3" and args[1] == "--version":
            return b"pip 20.0.2 from /usr/lib/python3/dist-packages/pip (python 3.8)"
        raise subprocess.CalledProcessError(1, args, output=b"subprocess error")

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)

    parser = PythonRequirementsParser(cve_db=None, logger=logger)
    # Execute the checker; it should trigger the error branch.
    list(parser.run_checker(str(req_file)))

    # Verify error messages were logged; decode bytes if needed
    assert any(
        "subprocess error" in (msg.decode() if isinstance(msg, bytes) else msg)
        for msg in logger.errors
    )
    assert any(
        "not scanned:" in (msg.decode() if isinstance(msg, bytes) else msg)
        for msg in logger.errors
    )


# Test for PythonParser exception handling (AttributeError branch)
def test_python_parser_attribute_error(tmp_path, monkeypatch):
    # Create dummy metadata file without proper Name/Version lines.
    meta_file = tmp_path / "METADATA.txt"
    meta_file.write_text("Invalid content without proper metadata")

    logger = DummyLogger()

    # Patch parse_strings to return invalid metadata.
    monkeypatch.setattr(
        "cve_bin_tool.parsers.python.parse_strings", lambda filename: "Invalid content"
    )

    parser = PythonParser(cve_db=None, logger=logger)
    list(parser.run_checker(str(meta_file)))

    # Verify the debug message for invalid metadata was logged.
    assert any("is an invalid METADATA/PKG-INFO" in msg for msg in logger.debugs)
