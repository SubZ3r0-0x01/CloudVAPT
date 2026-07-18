import os
import json
import re
import sys
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None  # Not used but required to be present per spec

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)


class AutomatedCloudIaCSecurityScanner:
    """
    Scans Terraform and CloudFormation templates for common security
    misconfigurations, compliance violations, and insecure defaults.
    Supports AWS, Azure, and GCP cloud providers.
    """

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None,
                 custom_rules_path: Optional[str] = None):
        """
        Initialize scanner with optional custom rules or path to rules JSON.

        :param rules: List of rule dictionaries.
        :param custom_rules_path: Path to a JSON file containing rules.
        """
        self.rules = rules or self._load_default_rules()
        if custom_rules_path:
            self._load_custom_rules(custom_rules_path)
        self.scanned_files = []
        self.findings = []

    def _load_default_rules(self) -> List[Dict[str, Any]]:
        """
        Load default security rules for AWS, Azure, and GCP.
        Returns a list of rule dictionaries.
        """
        return [
            # AWS
            {
                "id": "AWS-SG-001",
                "provider": "aws",
                "resource_type": "aws_security_group",
                "pattern": "ingress.*cidr_blocks.*[\"']0\\.0\\.0\\.0/0[\"']",
                "severity": "HIGH",
                "description": "Security group allows inbound traffic from 0.0.0.0/0"
            },
            {
                "id": "AWS-SG-002",
                "provider": "aws",
                "resource_type": "aws_security_group",
                "pattern": "ingress.*ipv6_cidr_blocks.*[\"']::/0[\"']",
                "severity": "HIGH",
                "description": "Security group allows inbound traffic from ::/0"
            },
            {
                "id": "AWS-EBS-001",
                "provider": "aws",
                "resource_type": "aws_ebs_volume",
                "pattern": "encrypted\\s*=\\s*false",
                "severity": "HIGH",
                "description": "EBS volume is not encrypted"
            },
            {
                "id": "AWS-S3-001",
                "provider": "aws",
                "resource_type": "aws_s3_bucket",
                "pattern": "server_side_encryption_configuration",
                "severity": "MEDIUM",
                "description": "S3 bucket is missing server-side encryption configuration",
                "negate": True
            },
            {
                "id": "AWS-IAM-001",
                "provider": "aws",
                "resource_type": "aws_iam_policy",
                "pattern": "Action\\s*=\\s*[\"']\\*[\"']",
                "severity": "HIGH",
                "description": "IAM policy allows all actions (*)"
            },
            {
                "id": "AWS-IAM-002",
                "provider": "aws",
                "resource_type": "aws_iam_policy",
                "pattern": "Resource\\s*=\\s*[\"']\\*[\"']",
                "severity": "HIGH",
                "description": "IAM policy allows all resources (*)"
            },
            {
                "id": "AWS-RDS-001",
                "provider": "aws",
                "resource_type": "aws_db_instance",
                "pattern": "publicly_accessible\\s*=\\s*true",
                "severity": "HIGH",
                "description": "RDS instance is publicly accessible"
            },
            # Azure
            {
                "id": "AZURE-NSG-001",
                "provider": "azure",
                "resource_type": "azurerm_network_security_rule",
                "pattern": "source_address_prefixes\\s*=\\s*[\"']\\*[\"']",
                "severity": "HIGH",
                "description": "Network security rule allows traffic from any source (*)"
            },
            {
                "id": "AZURE-STORAGE-001",
                "provider": "azure",
                "resource_type": "azurerm_storage_account",
                "pattern": "enable_https_traffic_only\\s*=\\s*false",
                "severity": "MEDIUM",
                "description": "Storage account does not enforce HTTPS traffic"
            },
            {
                "id": "AZURE-SQL-001",
                "provider": "azure",
                "resource_type": "azurerm_mssql_server",
                "pattern": "public_network_access_enabled\\s*=\\s*true",
                "severity": "HIGH",
                "description": "SQL server allows public network access"
            },
            # GCP
            {
                "id": "GCP-FW-001",
                "provider": "gcp",
                "resource_type": "google_compute_firewall",
                "pattern": "source_ranges\\s*=\\s*[\"']0\\.0\\.0\\.0/0[\"']",
                "severity": "HIGH",
                "description": "Firewall rule allows traffic from 0.0.0.0/0"
            },
            {
                "id": "GCP-SQL-001",
                "provider": "gcp",
                "resource_type": "google_sql_database_instance",
                "pattern": "require_ssl\\s*=\\s*false",
                "severity": "HIGH",
                "description": "Cloud SQL instance does not require SSL"
            },
            {
                "id": "GCP-GCS-001",
                "provider": "gcp",
                "resource_type": "google_storage_bucket",
                "pattern": "uniform_bucket_level_access\\s*=\\s*false",
                "severity": "MEDIUM",
                "description": "Storage bucket does not have uniform access control"
            },
        ]

    def _load_custom_rules(self, path: str) -> None:
        """
        Load custom rules from a JSON file.

        :param path: Path to JSON rules file.
        """
        try:
            with open(path, 'r') as f:
                custom_rules = json.load(f)
                if isinstance(custom_rules, list):
                    self.rules.extend(custom_rules)
                elif isinstance(custom_rules, dict):
                    self.rules.append(custom_rules)
                logger.info(f"Loaded {len(custom_rules)} custom rule(s) from {path}")
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.error(f"Failed to load custom rules from {path}: {e}")

    def scan(self, paths: List[str]) -> List[Dict[str, Any]]:
        """
        Scan one or more IaC files for security issues.

        :param paths: List of file paths to scan.
        :return: List of findings.
        """
        self.findings = []
        for path in paths:
            if not os.path.isfile(path):
                logger.warning(f"Skipping non-file: {path}")
                continue
            file_ext = Path(path).suffix.lower()
            logger.info(f"Scanning {path}...")
            try:
                if file_ext == '.tf':
                    findings = self._scan_terraform(path)
                elif file_ext in ('.json', '.yaml', '.yml'):