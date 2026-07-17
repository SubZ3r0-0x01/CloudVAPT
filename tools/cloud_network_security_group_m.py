#!/usr/bin/env python3
"""
Cloud Network Security Group Misconfiguration Detection Module.

Automatically scans cloud network security groups and firewall rules for
overly permissive inbound/outbound access across AWS, Azure, and GCP.
Identifies misconfigurations like open SSH, RDP, or all traffic from any source.
"""

import copy
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# --------------------------------------------------------------------------- #
#   Logger setup
# --------------------------------------------------------------------------- #
logger = logging.getLogger("CloudSecGroupScanner")
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(_handler)


class CloudNetworkSecurityGroupMisconfigurationDetection:
    """
    Scans and analyses cloud network security groups and firewall rules for
    misconfigurations that could lead to unauthorised network access.

    Supports AWS, Azure, and GCP.  Credentials are supplied via environment
    variables or passed directly to the constructor.

    Typical usage::

        scanner = CloudNetworkSecurityGroupMisconfigurationDetection()
        findings = scanner.scan_all()
        report = scanner.generate_report(findings)
        print(report)
    """

    # ------------------------------------------------------------------ #
    #   Constants for dangerous rule patterns
    # ------------------------------------------------------------------ #
    DANGEROUS_PORTS = {
        22: "SSH",
        3389: "RDP",
        21: "FTP",
        23: "Telnet",
        3306: "MySQL",
        5432: "PostgreSQL",
        1433: "MSSQL",
        6379: "Redis",
        27017: "MongoDB",
    }
    DANGEROUS_PROTOCOLS = {"tcp", "udp", "all"}
    ALL_CIDRS = {"0.0.0.0/0", "::/0"}

    def __init__(
        self,
        aws_access_key: Optional[str] = None,
        aws_secret_key: Optional[str] = None,
        aws_region: Optional[str] = None,
        azure_client_id: Optional[str] = None,
        azure_client_secret: Optional[str] = None,
        azure_tenant_id: Optional[str] = None,
        azure_subscription_id: Optional[str] = None,
        gcp_service_account_json: Optional[str] = None,
        gcp_project: Optional[str] = None,
    ) -> None:
        """
        Initialise the scanner with optional cloud credentials.

        If credentials are not provided, the module will attempt to read them
        from environment variables:

        - **AWS**: ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, ``AWS_DEFAULT_REGION``
        - **Azure**: ``AZURE_CLIENT_ID``, ``AZURE_CLIENT_SECRET``, ``AZURE_TENANT_ID``, ``AZURE_SUBSCRIPTION_ID``
        - **GCP**: ``GCP_SERVICE_ACCOUNT_JSON`` (full path to JSON key file), ``GCP_PROJECT``

        :param aws_access_key: AWS access key ID.
        :param aws_secret_key: AWS secret access key.
        :param aws_region: AWS region (default 'us-east-1').
        :param azure_client_id: Azure service principal client ID.
        :param azure_client_secret: Azure service principal secret.
        :param azure_tenant_id: Azure AD tenant ID.
        :param azure_subscription_id: Azure subscription ID.
        :param gcp_service_account_json: Path to GCP service account JSON key file.
        :param gcp_project: GCP project ID.
        """
        # AWS
        self.aws_access_key = aws_access_key or os.environ.get("AWS_ACCESS_KEY_ID")
        self.aws_secret_key = aws_secret_key or os.environ.get("AWS_SECRET_ACCESS_KEY")
        self.aws_region = aws_region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

        # Azure
        self.azure_client_id = azure_client_id or os.environ.get("AZURE_CLIENT_ID")
        self.azure_client_secret = azure_client_secret or os.environ.get("AZURE_CLIENT_SECRET")
        self.azure_tenant_id = azure_tenant_id or os.environ.get("AZURE_TENANT_ID")
        self.azure_subscription_id = azure_subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID")

        # GCP
        self.gcp_service_account_json = gcp_service_account_json or os.environ.get("GCP_SERVICE_ACCOUNT_JSON")
        self.gcp_project = gcp_project or os.environ.get("GCP_PROJECT")

        self._azure_token: Optional[str] = None
        self._gcp_token: Optional[str] = None

    # ------------------------------------------------------------------ #
    #   Public API
    # ------------------------------------------------------------------ #

    def scan_all(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run scans on all configured cloud providers.

        :returns: Dictionary keyed by cloud provider (aws|azure|gcp) containing
                  lists of findings (each finding is a dict with details).
        """
        findings: Dict[str, List[Dict[str, Any]]] = {}
        if self.aws_access_key and self.aws_secret_key:
            logger.info("Scanning AWS...")
            findings["aws"] = self.scan_aws()
        else:
            logger.info("Skipping AWS (no credentials)")

        if all([self.azure_client_id, self.azure_client_secret, self.azure_tenant_id, self.azure_subscription_id]):
            logger.info("Scanning Azure...")
            findings["azure"] = self.scan_azure()
        else:
            logger.info("Skipping Azure (no credentials)")

        if self.gcp_service_account_json and self.gcp_project:
            logger.info("Scanning GCP...")
            findings["gcp"] = self.scan_gcp()
        else:
            logger.info("Skipping GCP (no credentials)")

        return findings

    def scan_aws(self) -> List[Dict[str, Any]]:
        """
        Scan AWS EC2 Security Groups via DescribeSecurityGroups API.

        :returns: List of misconfiguration findings.
        :raises RuntimeError: If API call fails.
        """
        # Fetch security groups
        payload = self._aws_api_call("ec2", "DescribeSecurityGroups", {})
        if "SecurityGroups" not in payload:
            logger.error("Unexpected AWS response: %s", payload)
            return []

        findings = []
        for sg in payload["SecurityGroups"]:
            group_id = sg["GroupId"]
            group_name = sg.get("GroupName", "unknown")
            vpc_id = sg.get("VpcId", "none")
            for rule_list, direction in [(sg.get("IpPermissions", []), "inbound"),
                                          (sg.get("IpPermissionsEgress", []), "outbound")]:
                for rule in rule_list:
                    findings += self._analyse_aws_rule(rule, group_id, group_name, vpc_id, direction)
        return findings

    def scan_azure(self) -> List[Dict[str, Any]]:
        """
        Scan Azure Network Security Groups using Azure REST API.

        :returns: