# Copyright (C) 2024 Intel Corporation
# SPDX-License-Identifier: GPL-3.0-or-later

from logging import Logger
from pathlib import Path
from typing import Dict, List, Optional

from lib4sbom.data.vulnerability import Vulnerability
from lib4vex.generator import VEXGenerator

from cve_bin_tool.log import LOGGER
from cve_bin_tool.util import CVEData, ProductInfo, Remarks


class VEXGenerate:
    """
    A class for generating VEX (Vulnerability Exploitability eXchange) documents.

    This class maintains the state of vulnerability analysis for different VEX types,
    including CycloneDX, CSAF, and OpenVEX. The `analysis_state` dictionary maps
    remarks related to vulnerability status to their corresponding states for each
    VEX type.

    Attributes:
        analysis_state (dict): A dictionary containing the mapping of remarks to
        analysis states for different VEX types. The keys are the VEX types ("cyclonedx",
        "csaf", "openvex"), and the values are dictionaries mapping `Remarks` enum values
        to their corresponding vulnerability analysis states.

    Example:
        >>> vex_gen = VEXGenerate()
        >>> state = vex_gen.analysis_state["cyclonedx"][Remarks.Confirmed]
        >>> print(state)  # Output: "exploitable"
    """

    analysis_state = {
        "cyclonedx": {
            Remarks.NewFound: "in_triage",
            Remarks.Unexplored: "in_triage",
            Remarks.Confirmed: "exploitable",
            Remarks.Mitigated: "resolved",
            Remarks.FalsePositive: "false_positive",
            Remarks.NotAffected: "not_affected",
        },
        "csaf": {
            Remarks.NewFound: "under_investigation",
            Remarks.Unexplored: "under_investigation",
            Remarks.Confirmed: "known_affected",
            Remarks.Mitigated: "fixed",
            Remarks.FalsePositive: "known_not_affected",
            Remarks.NotAffected: "known_not_affected",
        },
        "openvex": {
            Remarks.NewFound: "under_investigation",
            Remarks.Unexplored: "under_investigation",
            Remarks.Confirmed: "affected",
            Remarks.Mitigated: "fixed",
            Remarks.FalsePositive: "not_affected",
            Remarks.NotAffected: "not_affected",
        },
    }

    def __init__(
        self,
        product: str,
        release: str,
        vendor: str,
        filename: str,
        vextype: str,
        all_cve_data: Dict[ProductInfo, CVEData],
        revision_reason: str = "",
        sbom_serial_number: str = "",
        sbom: Optional[str] = None,
        logger: Optional[Logger] = None,
        validate: bool = True,
    ):
        """
        Initializes a VEXGenerate instance with specified product, release, and other parameters
        for managing CVE data and generating vulnerability exchange (VEX) documents.

        Parameters:
            product (str): The name of the product being analyzed.
            release (str): The product release version.
            vendor (str): The name of the product vendor.
            filename (str): The filename to use for generated VEX data.
            vextype (str): The type of VEX document.
            all_cve_data (Dict[ProductInfo, CVEData]): Dictionary containing CVE data by product.
            revision_reason (str, optional): Reason for the VEX document revision. Defaults to "".
            sbom_serial_number (str, optional): The serial number for the software bill of materials. Defaults to "".
            sbom (Optional[str], optional): Software bill of materials, if available. Defaults to None.
            logger (Optional[Logger], optional): Logger instance for logging. Defaults to None.
            validate (bool, optional): Flag indicating if input validation is required. Defaults to True.
        """
        self.product = product
        self.release = release
        self.vendor = vendor
        self.revision_reason = revision_reason
        self.sbom = sbom
        self.filename = filename
        self.vextype = vextype
        self.logger = logger or LOGGER.getChild(self.__class__.__name__)
        self.validate = validate
        self.all_cve_data = all_cve_data
        self.sbom_serial_number = sbom_serial_number

    def generate_vex(self) -> None:
        """
        Generates a VEX (Vulnerability Exploitability eXchange) document based on the specified VEX type
        and stores it in the given filename.

        This method sets up a VEX generator instance with the product name, release version, and other
        metadata. It automatically assigns a filename if none is provided, logs the update status if the
        file already exists, and generates the VEX document with product vulnerability data.

        Returns:
            None
        """
        author = "Unknown Author"
        if self.vendor:
            author = self.vendor
        vexgen = VEXGenerator(vex_type=self.vextype, author=author)
        kwargs = {"name": self.product, "release": self.release}
        if self.sbom:
            kwargs["sbom"] = self.sbom
        vexgen.set_product(**kwargs)
        if not self.filename:
            self.logger.info(
                "No filename defined, generating a new filename with default naming convention."
            )
            self.filename = self.__generate_vex_filename()
        if Path(self.filename).is_file():
            self.logger.info(f"Updating the VEX file: {self.filename}")

        vexgen.generate(
            project_name=self.product,
            vex_data=self.__get_vulnerabilities(),
            metadata=self.__get_metadata(),
            filename=self.filename,
        )

    def __generate_vex_filename(self) -> str:
        """
        Generates a default VEX filename using the product, release, vendor, and VEX type information.

        The filename is structured as "{product}_{release}_{vendor}_{vextype}.json" and is saved in the
        current working directory.

        Returns:
            str: The generated VEX filename as a string.
        """
        filename = (
            Path.cwd()
            / f"{self.product}_{self.release}_{self.vendor}_{self.vextype}.json"
        )
        return str(filename)

    def __get_metadata(self) -> Dict:
        """
        Generates metadata for the VEX document based on the specified VEX type, product, release,
        and vendor information.

        This method creates a dictionary containing metadata fields, such as `id`, `supplier`,
        `author`, and `revision_reason`, depending on the VEX type. Metadata fields are populated
        according to the VEX format requirements, such as "cyclonedx," "csaf," or "openvex".

        Returns:
            Dict: A dictionary containing the metadata for the VEX document.
        """
        metadata = {}
        if self.vextype == "cyclonedx":
            if self.product:
                metadata["id"] = f"{self.product.upper()}-VEX"
        elif self.vextype == "csaf":
            if self.product and self.release and self.vendor:
                metadata["id"] = f"{self.product.upper()}-{self.release}-VEX"
                metadata["supplier"] = self.vendor
        elif self.vextype == "openvex":
            if self.vendor:
                metadata["author"] = self.vendor
                metadata["supplier"] = self.vendor
        if self.revision_reason:
            metadata["revision_reason"] = self.revision_reason

        return metadata

    def __get_vulnerabilities(self) -> List[Vulnerability]:
        """
        Retrieves and constructs a list of vulnerability objects based on the current CVE data.

        This method iterates through all CVE data associated with the product and vendor,
        creating and configuring `Vulnerability` objects for each entry. It sets attributes
        like name, release, ID, description, status, and additional metadata such as package
        URLs (purl) and bill of materials (BOM) links. If a vulnerability includes comments
        or justification, these are added to the vulnerability details.

        Returns:
            List[Vulnerability]: A list of `Vulnerability` objects representing the identified
            vulnerabilities, enriched with metadata and details.
        """
        vulnerabilities = []
        for product_info, cve_data in self.all_cve_data.items():
            vendor, product, version, purl = product_info
            for cve in cve_data["cves"]:
                if isinstance(cve, str):
                    continue
                vulnerability = Vulnerability(validation=self.vextype)
                vulnerability.initialise()
                vulnerability.set_name(product)
                vulnerability.set_release(version)
                vulnerability.set_id(cve.cve_number)
                vulnerability.set_description(cve.description)
                vulnerability.set_comment(cve.comments)
                vulnerability.set_status(self.analysis_state[self.vextype][cve.remarks])
                if cve.justification:
                    vulnerability.set_justification(cve.justification)
                if cve.response:
                    vulnerability.set_value("remediation", cve.response[0])
                detail = (
                    f"{cve.remarks.name}: {cve.comments}"
                    if cve.comments
                    else cve.remarks.name
                )
                if purl is None:
                    purl = f"pkg:generic/{vendor}/{product}@{version}"
                bom_version = 1
                if self.sbom_serial_number != "":
                    ref = f"urn:cdx:{self.sbom_serial_number}/{bom_version}#{purl}"
                else:
                    ref = f"urn:cbt:{bom_version}/{vendor}#{product}:{version}"

                vulnerability.set_value("purl", str(purl))
                vulnerability.set_value("bom_link", ref)
                vulnerability.set_value("action", detail)
                vulnerability.set_value("source", cve.data_source)
                vulnerability.set_value("updated", cve.last_modified)
                vulnerabilities.append(vulnerability.get_vulnerability())
        self.logger.debug(f"Vulnerabilities: {vulnerabilities}")
        return vulnerabilities
