import json
import re
import os
import sys
import logging
from typing import Any, Dict, List, Optional, Union
from copy import deepcopy

import requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IaCSecurityScanner:
    """
    Automated Cloud Infrastructure as Code (IaC) Security Scanner

    Scans Terraform (.tf) and CloudFormation (.json) templates for security
    misconfigurations, compliance violations (CIS benchmarks), and insecure patterns.
    For Terraform, simple HCL parsing is performed via regular expressions.
    CloudFormation templates must be provided as JSON.

    Supports AWS, Azure, and GCP providers.

    Example usage:
        scanner = IaCSecurityScanner()
        findings = scanner.scan('path/to/template.tf', provider='aws')
        print(scanner.generate_report(format='json'))
    """

    # Regex to extract Terraform resource blocks
    RESOURCE_BLOCK_RE = re.compile(
        r'resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{',
        re.MULTILINE
    )

    def __init__(
        self,
        rules: Optional[Dict[str, Any]] = None,
        rules_url: Optional[str] = None
    ):
        """
        Initialize the scanner with optional custom rules and remote rule endpoint.

        Args:
            rules: Dictionary of custom rules to override defaults.
            rules_url: URL to fetch additional rules (JSON format) at initialization.
        """
        self.rules = self._default_rules()
        if rules:
            self.rules.update(rules)
        if rules_url:
            try:
                logger.info(f"Fetching rules from {rules_url}")
                response = requests.get(rules_url, timeout=10)
                response.raise_for_status()
                remote_rules = response.json()
                if isinstance(remote_rules, dict):
                    self.rules.update(remote_rules)
                    logger.info(f"Loaded {len(remote_rules)} remote rules")
                else:
                    logger.warning("Remote rules are not a dict, ignoring")
            except Exception as e:
                logger.error(f"Failed to fetch rules from {rules_url}: {e}")

        self.findings: List[Dict[str, Any]] = []

    def load_file(self, filepath: str) -> Dict[str, Any]:
        """
        Load and parse an IaC template file.

        Supports Terraform (.tf) and CloudFormation (.json) files.
        For .tf files, a simple parser extracts resource blocks.
        For .json files, the entire JSON structure is returned.

        Args:
            filepath: Path to the template file.

        Returns:
            Dictionary containing parsed resources and metadata.

        Raises:
            FileNotFoundError: If file does not exist.
            ValueError: If file format is unsupported or parsing fails.
        """
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        _, ext = os.path.splitext(filepath)
        ext = ext.lower()

        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()

        if ext == '.tf':
            return self._parse_terraform(content)
        elif ext == '.json':
            return self._parse_cloudformation(content)
        else:
            raise ValueError(f"Unsupported file extension: {ext}. Use .tf or .json")

    def _parse_terraform(self, content: str) -> Dict[str, Any]:
        """
        Parse Terraform HCL content using regex to extract resource blocks.

        Args:
            content: Raw HCL content.

        Returns:
            Dictionary with key 'resources' containing a list of resource dicts.
        """
        resources = []
        lines = content.splitlines()
        # Simple state machine to capture block content
        # For production, consider using a proper HCL parser;
        # this regex-based version works for simple cases.
        stack = []  # tracks braces
        current_resource = None
        for i, line in enumerate(lines):
            # Try to match resource declaration
            match = self.RESOURCE_BLOCK_RE.search(line)
            if match:
                # Check that we are not inside another block
                if not stack:
                    current_resource = {
                        'type': match.group('type'),
                        'name': match.group('name'),
                        'attributes': {},
                        'raw_block': ''
                    }
                    stack.append('{')
                    # capture the line as start of block
                    current_resource['raw_block'] = line + '\n'
                else:
                    logger.warning(f"Nested resource declaration at line {i+1}, ignoring")
                continue

            if current_resource is None:
                continue

            # Track braces to know when the block ends
            open_braces = line.count('{')
            close_braces = line.count('}')
            for _ in range(open_braces):
                stack.append('{')
            for _ in range(close_braces):
                if stack:
                    stack.pop()

            # Append line to raw_block
            current_resource['raw_block'] += line + '\n'

            # If stack is empty and we are in a resource, it's complete
            if not stack and current_resource:
                self._extract_terraform_attributes(current_resource)
                resources.append(current_resource)
                current_resource = None

        # In case file ends inside block (malformed)
        if current_resource is not None:
            logger.warning("Unterminated resource block at end of file")
            self._extract_terraform_attributes(current_resource)
            resources.append(current_resource)

        return {'resources': resources}

    def _extract_terraform_attributes(self, resource: Dict[str, Any]) -> None:
        """
        Extract key=value attributes from raw block text.

        Simple regex approach for demonstration.
        """
        pattern = re.compile(r'^\s*(\w+)\s*=\s*["\']?(.*?)["\']?\s*$', re.MULTILINE)
        for match in pattern.finditer(resource['raw_block']):
            key = match.group(1)
            val = match.group(2)
            # For list/map values, more complex parsing would be needed.
            # This is a simplified version.
            resource['attributes'][key] = val

    def _parse_cloudformation(self, content: str) -> Dict[str, Any]:
        """
        Parse CloudFormation JSON content.

        Args:
            content: JSON string.

        Returns:
            Dictionary with keys 'resources' and full parsed template.

        Raises:
            ValueError: If JSON is invalid.
        """
        try:
            template = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON file: {e}")

        resources = []
        cfn_resources = template.get('Resources', {})
        for logical_id, resource_spec in cfn_resources.items():
            resources.append({
                'logical_id': logical_id,
                'type': resource_spec.get('Type'),
                'properties': resource_spec.get('Properties', {})
            })

        return {'resources': resources, 'template': template}

    def _default_rules(self) -> Dict[str, Any]:
        """
        Define default security rules covering common misconfigurations.

        Returns a dictionary where each key is a rule ID and value is a dict:
            - id: str
            - name: str
            - description: str
            - severity: str (HIGH, MEDIUM, LOW)
            - provider: str (aws, azure, gcp)
            - applies_to: function(resource, provider) -> bool (True if rule matches)
        """
        rules = {}

        # AWS: Security group open to 0.0.0.0/0
        rules['AWS-SG-OPEN-ALL'] = {
            'id': 'AWS-SG-OPEN-ALL',
            'name': 'Security group allows inbound traffic from 0.0.0.0/0',
            'description': 'Avoid security groups allowing inbound traffic from any IP.',
            'severity': 'HIGH',
            'provider': 'aws',
            'applies_to': lambda resource, provider: (
                provider == 'aws' and
                resource.get('type', '').endswith('aws_security_group') and
                'cidr_blocks' in resource.get('attributes', {}) and
                '