import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from test.utils import LONG_TESTS
from unittest.mock import patch

import pytest

from mismatch.cli import main


@pytest.fixture(scope="module")
def test_db(tmpdir_factory):
    db_file = tmpdir_factory.mktemp("data").join("test_mismatch.db")
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE mismatch (purl TEXT, vendor TEXT)")
    cursor.executemany(
        "INSERT INTO mismatch (purl, vendor) VALUES (?, ?)",
        [
            ("pkg:namespace/product1", "Vendor1"),
            ("pkg:namespace/product2", "Vendor2"),
            ("pkg:namespace/product1", "Vendor3"),
        ],
    )
    conn.commit()
    conn.close()
    yield str(db_file)


@pytest.fixture(scope="module")
def build_cleanup():
    yield
    dist_dir = Path(__file__).resolve().parent.parent / "dist"
    if dist_dir.exists():
        shutil.rmtree(dist_dir)


def test_lookup(capsys, monkeypatch, test_db):
    # Test with custom database path using the --database flag
    monkeypatch.setattr(
        "sys.argv", ["main", "lookup", "pkg:namespace/product1", "--database", test_db]
    )
    main()
    captured = capsys.readouterr()
    assert "Vendor1, Vendor3" in captured.out

    # Test with default database path (without --database flag)
    monkeypatch.setattr("mismatch.cli.dbpath", test_db)
    monkeypatch.setattr("sys.argv", ["main", "lookup", "pkg:namespace/product1"])
    main()
    captured = capsys.readouterr()
    assert "Vendor1, Vendor3" in captured.out

    # Test with a non-existing purl
    monkeypatch.setattr(
        "sys.argv",
        ["main", "lookup", "pkg:namespace/non_existing_product", "--database", test_db],
    )
    main()
    captured = capsys.readouterr()
    assert "Error: No data found for the provided purl." in captured.out


def test_loader(monkeypatch, tmpdir, test_db):
    # Test with custom directory and database path using the --dir and --database flags
    data_dir = Path(__file__).resolve().parent.parent / "mismatch_data"
    monkeypatch.setattr(
        "sys.argv", ["main", "loader", "--dir", str(data_dir), "--database", test_db]
    )

    with patch("cve_bin_tool.mismatch_loader.run_mismatch_loader"):
        main()

        verify_db(test_db)

    # Test with default directory and database path (without --dir and --database flags)
    monkeypatch.setattr("mismatch.cli.data_dir", data_dir)
    monkeypatch.setattr("mismatch.cli.dbpath", test_db)
    monkeypatch.setattr("sys.argv", ["main", "loader"])

    with patch("cve_bin_tool.mismatch_loader.run_mismatch_loader"):
        main()

        verify_db(test_db)

    # Test default command execution when invoked with just `mismatch`
    monkeypatch.setattr("sys.argv", ["main"])

    with patch("cve_bin_tool.mismatch_loader.run_mismatch_loader"):
        main()

        verify_db(test_db)


def verify_db(test_db):
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM mismatch;")
    result = cursor.fetchall()
    expected = (
        "pkg:pypi/zstandard",
        "facebook",
    )
    assert expected in result


@pytest.mark.skipif(not LONG_TESTS(), reason="Skipping long tests")
def test_package_build(build_cleanup):
    build = subprocess.run([sys.executable, "-m", "build"], check=True)
    assert build.returncode == 0, "Python build failed"

    dist_dir = Path(__file__).resolve().parent.parent / "dist"
    package_path = list(dist_dir.glob("*.whl"))[0]
    subprocess.run(["pip", "install", str(package_path)], check=True)

    result = subprocess.run(["mismatch", "--help"], capture_output=True, text=True)
    assert "ModuleNotFoundError: No module named 'mismatch'" not in result.stderr
