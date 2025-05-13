# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from json import dump, load
from pathlib import Path
from time import time

from cve_bin_tool.cve_scanner import CVEData
from cve_bin_tool.log import LOGGER
from cve_bin_tool.output_engine.util import ProductInfo, format_output
from cve_bin_tool.util import make_http_requests

JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
DEB_CVE_JSON_PATH = (
    Path("~").expanduser() / ".cache" / "cve-bin-tool" / "debian_cve_data.json"
)

UBUNTU_DEBIAN_MAP = {
    "hirsute": "bullseye",
    "groovy": "bullseye",
    "focal": "bullseye",
    "eoan": "buster",
    "disco": "buster",
    "cosmic": "buster",
    "bionic": "buster",
    "artful": "stretch",
    "zesty": "stretch",
    "yakkety": "stretch",
    "xenial": "stretch",
}


class DebianCVETracker:
    """
    A class for tracking CVEs (Common Vulnerabilities and Exposures) for Debian-based distributions.

    This class is designed to monitor CVEs specific to a given Debian distribution,
    taking into account the distribution name, codename, and whether the package is a backport.

    Attributes:
        distro_name (str): The name of the Debian-based distribution (e.g., "Debian", "Ubuntu").
        distro_codename (str): The codename of the distribution release (e.g., "buster", "focal").
        is_backport (bool): Flag indicating if the package is a backport.
    """

    def __init__(self, distro_name: str, distro_codename: str, is_backport: bool):
        """
        Initializes a DebianCVETracker instance with distribution information.

        Parameters:
            distro_name (str): The name of the Debian-based distribution.
            distro_codename (str): The codename for the distribution release.
            is_backport (bool): Specifies if the package is a backport.
        """
        self.distro_name = distro_name
        self.distro_codename = distro_codename
        self.is_backport = is_backport

    def cve_info(
        self,
        all_cve_data: dict[ProductInfo, CVEData],
    ):
        """
        Generates information on backported CVE fixes for a given set of CVE data.

        This function processes CVE data and checks for resolved vulnerabilities in
        the Debian or Ubuntu distributions. If a fix is available or backported, it logs
        relevant information about the fix's availability and version.

        Parameters:
            all_cve_data (dict[ProductInfo, CVEData]): Dictionary containing CVE data,
            organized by product and version.
        """

        cve_data = format_output(all_cve_data, None)
        json_data = self.get_data()
        for cve in cve_data:
            try:
                cve_fix = json_data[cve["product"]][cve["cve_number"]]["releases"][
                    self.compute_distro()
                ]
                if cve_fix["status"] == "resolved":
                    if self.is_backport:
                        if cve_fix["fixed_version"].startswith(cve["version"]):
                            LOGGER.info(
                                f'{cve["product"]}: {cve["cve_number"]} has backported fix in v{cve_fix["fixed_version"]} release.'
                            )
                        else:
                            LOGGER.info(
                                f'{cve["product"]}: No known backported fix for {cve["cve_number"]}.'
                            )
                    else:
                        LOGGER.info(
                            f'{cve["product"]}: {cve["cve_number"]} has available fix in v{cve_fix["fixed_version"]} release.'
                        )
            except KeyError:
                if cve["cve_number"] != "UNKNOWN":
                    LOGGER.info(
                        f'{cve["product"]}: No known fix for {cve["cve_number"]}.'
                    )

    def get_data(self):
        """
        Retrieves CVE data from the Debian CVE JSON file.

        This method opens and loads the Debian CVE JSON file for processing
        vulnerability data, calling `check_json` to verify that the file is
        up-to-date before loading.

        Returns:
            dict: Loaded JSON data from the Debian CVE JSON file.
        """
        check_json()
        with open(DEB_CVE_JSON_PATH) as jsonfile:
            return load(jsonfile)

    def compute_distro(self):
        """
        Computes the distribution codename based on the Debian or Ubuntu release.

        Maps the specified distribution codename to either Ubuntu or Debian based
        on the provided `distro_name`.

        Returns:
            str: The mapped codename for the distribution.
        """
        if self.distro_name == "ubuntu":
            return UBUNTU_DEBIAN_MAP[self.distro_codename]
        elif self.distro_name == "debian":
            return self.distro_codename


def check_json():
    """
    Verifies if the Debian CVE JSON file is current and triggers an update if outdated.

    This function checks the modification time of the JSON file. If it's older than
    one day, it calls `update_json` to download a fresh version.
    """

    if (
        not DEB_CVE_JSON_PATH.exists()
        or DEB_CVE_JSON_PATH.stat().st_mtime + (24 * 60 * 60) < time()
    ):
        update_json()


def update_json():
    """
    Updates the Debian CVE JSON file by downloading the latest data.

    This function requests the JSON data from the specified URL and saves it to
    the `DEB_CVE_JSON_PATH` location, logging the update status.
    """

    LOGGER.info("Updating Debian CVE JSON file for checking available fixes.")
    # timeout = 300s = 5min. This is a guess at a valid default
    response = make_http_requests("json", url=JSON_URL, timeout=300)
    with open(DEB_CVE_JSON_PATH, "w") as debian_json:
        dump(response, debian_json, indent=4)
        LOGGER.info("Debian CVE JSON file for checking available fixes is updated.")
