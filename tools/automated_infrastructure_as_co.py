import json
import argparse
import sys
import os
from typing import List, Dict, Any, Optional


class IaCSecurityScanner:
    """
    Automated scanner for Infrastructure as Code (IaC) security misconfigurations
    and compliance violations. Supports Terraform (JSON plan), CloudFormation,
    and ARM templates in JSON format.
    """

    def __init__(self, rules: Optional[List[Dict[str, Any]]] = None) -> None:
        """
        Initialize the scanner with an optional custom rules list.
        If no rules are provided, built-in default rules are used.

        Args:
            rules: A list of rule dictionaries. Each rule should have:
                   - provider: 'aws', 'azure', 'gcp'
                   - description: str
                   - severity: 'high' | 'medium' | 'low'
                   - check: callable(parsed_content: dict) -> list of findings
        """
        self.rules = rules if rules is not None else self._default_rules()
        self.findings: List[Dict[str, Any]] = []

    def _default_rules(self) -> List[Dict[str, Any]]:
        """Define the built-in security rules per provider."""
        return [
            # AWS rules
            {
                'provider': 'aws',
                'resource_type': 'aws_security_group_rule',
                'description': 'Security group rule with open ingress (0.0.0.0/0)',
                'severity': 'high',
                'check': self._check_aws_open_sg
            },
            {
                'provider': 'aws',
                'resource_type': 'aws_s3_bucket',
                'description': 'S3 bucket with no server-side encryption',
                'severity': 'high',
                'check': self._check_aws_unencrypted_s3
            },
            {
                'provider': 'aws',
                'resource_type': 'aws_iam_policy',
                'description': 'IAM policy with overly permissive action and resource',
                'severity': 'high',
                'check': self._check_aws_overly_permissive_iam
            },
            # Azure rules
            {
                'provider': 'azure',
                'resource_type': 'azurerm_network_security_rule',
                'description': 'Network security rule with open inbound access (0.0.0.0/0)',
                'severity': 'high',
                'check': self._check_azure_open_nsg
            },
            {
                'provider': 'azure',
                'resource_type': 'azurerm_storage_account',
                'description': 'Storage account with encryption disabled',
                'severity': 'high',
                'check': self._check_azure_unencrypted_storage
            },
            {
                'provider': 'azure',
                'resource_type': 'azurerm_role_definition',
                'description': 'Custom role with wildcard action/resource',
                'severity': 'high',
                'check': self._check_azure_overly_permissive_role
            },
            # GCP rules
            {
                'provider': 'gcp',
                'resource_type': 'google_compute_firewall',
                'description': 'Firewall rule allowing inbound from 0.0.0.0/0',
                'severity': 'high',
                'check': self._check_gcp_open_firewall
            },
            {
                'provider': 'gcp',
                'resource_type': 'google_storage_bucket',
                'description': 'Cloud Storage bucket with no encryption',
                'severity': 'high',
                'check': self._check_gcp_unencrypted_storage
            },
            {
                'provider': 'gcp',
                'resource_type': 'google_iam_policy',
                'description': 'IAM policy with broad permissions',
                'severity': 'high',
                'check': self._check_gcp_overly_permissive_iam
            },
        ]

    def add_rule(self, rule: Dict[str, Any]) -> None:
        """
        Add a custom rule to the scanner.

        Args:
            rule: Rule dictionary with provider, description, severity, check.
        """
        self.rules.append(rule)

    def scan_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Scan an IaC file (JSON) for security issues.

        Args:
            file_path: Path to the JSON file.

        Returns:
            A list of findings (each finding is a dict with keys:
            resource, type, severity, description).
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Determine provider based on file name or content
        provider = self._detect_provider(file_path, content)
        return self.scan_content(content, provider)

    def scan_content(self, content: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan IaC content (JSON string) for security issues.

        Args:
            content: The JSON content as a string.
            provider: One of 'aws', 'azure', 'gcp'. If None, it is auto-detected.

        Returns:
            List of findings.
        """
        if provider is None:
            provider = self._detect_provider_from_content(content)

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        self.findings = []
        applicable_rules = [r for r in self.rules if r['provider'] == provider]

        for rule in applicable_rules:
            findings = rule['check'](parsed)
            self.findings.extend(findings)

        return self.findings

    def _detect_provider(self, file_path: str, content: str) -> str:
        """Detect provider from file path and content."""
        # First try by filename patterns
        basename = os.path.basename(file_path).lower()
        if basename.startswith('terraform') or basename == 'plan.json':
            return 'aws'  # Terraform is cloud-agnostic, but we treat as aws for check selection
        if 'cloudformation' in basename or 'cfn' in basename or basename == 'template.json':
            return 'aws'
        if 'arm' in basename or 'azuredeploy' in basename:
            return 'azure'
        if basename.startswith('gcp') or basename == 'deployment.json':
            return 'gcp'

        # Fallback to content detection
        return self._detect_provider_from_content(content)

    def _detect_provider_from_content(self, content: str) -> str:
        """Simple detection of provider based on known keywords in JSON."""
        low_content = content.lower()
        if '"azurerm"' in low_content or '"azure"' in low_content:
            return 'azure'
        if '"google_compute"' in low_content or '"google_storage"' in low_content or '"gcp"' in low_content:
            return 'gcp'
        # Default to AWS (common for Terra