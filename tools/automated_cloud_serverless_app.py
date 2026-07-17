import os
import json
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AutomatedCloudServerlessApplicationSecurityScanner:
    """
    Automated Cloud Serverless Application Security Scanner.

    Scans serverless functions across AWS Lambda, Azure Functions, and GCP Cloud Functions
    for over-permissive IAM roles, vulnerable dependencies, event injection risks, and insecure
    environment variable storage using static analysis and optional cloud provider API calls.
    Uses only standard library and requests (for future API-based checks).
    """

    # Common dangerous patterns for event injection
    EVENT_INJECTION_PATTERNS = [
        re.compile(r"\beval\s*\(", re.IGNORECASE),
        re.compile(r"\bexec\s*\(", re.IGNORECASE),
        re.compile(r"\bos\.system\s*\(", re.IGNORECASE),
        re.compile(r"\bsubprocess\.(call|Popen|run)\s*\(", re.IGNORECASE),
        re.compile(r"\b__import__\s*\(.*\brequest\b", re.IGNORECASE),
        re.compile(r"\binput\s*\(\)", re.IGNORECASE),
        re.compile(r"\braw_input\s*\(\)", re.IGNORECASE),
        re.compile(r"\bexecfile\s*\(", re.IGNORECASE),
    ]

    # Over-permissive IAM actions (wildcard or dangerous)
    OVER_PERMISSIVE_ACTIONS = [
        'iam:Create*', 'iam:Update*', 'iam:Delete*',
        'ec2:Describe*', 's3:*', 'lambda:*', 'kms:*',
        'secretsmanager:*', 'ssm:*',
    ]

    # Known vulnerable dependencies (simplified)
    VULNERABLE_DEPENDENCIES = {
        'requests': (['2.0.0', '2.25.0'], 'CVE-2022-12345'),
        'flask': (['0.10.0', '1.1.0'], 'CVE-2023-67890'),
        'django': (['1.0.0', '3.2.0'], 'CVE-2023-11223'),
        'express': (['4.0.0', '4.17.0'], 'CVE-2022-33456'),
    }

    def __init__(self, rules: Optional[Dict[str, Any]] = None):
        """
        Initialize scanner with optional custom rules.

        :param rules: Dictionary with custom patterns or thresholds.
        """
        self.rules = rules or {}
        self.findings = []

    def scan_function(self, provider: str, function_path: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan a serverless function for security vulnerabilities.

        :param provider: Cloud provider ('aws', 'azure', 'gcp').
        :param function_path: Path to the function code directory or file.
        :param config_file: Path to a JSON/YAML configuration file for IAM roles or environment variables.
        :return: List of findings (each as dict).
        """
        findings = []
        logger.info(f"Scanning {provider} function at {function_path}")

        # Check path exists
        path = Path(function_path)
        if not path.exists():
            logger.error(f"Function path {function_path} does not exist")
            return [{"type": "error", "detail": f"Path {function_path} not found"}]

        # Load configuration if provided
        config = self._load_config(config_file) if config_file else {}

        # Perform individual checks
        findings.extend(self._check_iam_roles(config.get('iam_role', {})))
        findings.extend(self._check_vulnerable_dependencies(path))
        findings.extend(self._check_event_injection(path))
        findings.extend(self._check_env_vars(config.get('env_vars', {}), path))

        self.findings.extend(findings)
        return findings

    def scan_aws_lambda(self, function_path: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan AWS Lambda function.

        :param function_path: Path to function code.
        :param config_file: Optional config file.
        :return: List of findings.
        """
        return self.scan_function('aws', function_path, config_file)

    def scan_azure_functions(self, function_path: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan Azure Functions.

        :param function_path: Path to function code.
        :param config_file: Optional config file.
        :return: List of findings.
        """
        return self.scan_function('azure', function_path, config_file)

    def scan_gcp_cloud_functions(self, function_path: str, config_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Scan GCP Cloud Functions.

        :param function_path: Path to function code.
        :param config_file: Optional config file.
        :return: List of findings.
        """
        return self.scan_function('gcp', function_path, config_file)

    def scan_all(self, function_map: Dict[str, Dict[str, str]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scan multiple functions across providers.

        :param function_map: Dict with provider as key and dict containing 'path' and optional 'config'.
        :return: Nested dict with findings per provider.
        """
        all_findings = {}
        for provider, details in function_map.items():
            path = details.get('path', '')
            config = details.get('config', None)
            all_findings[provider] = self.scan_function(provider, path, config)
        return all_findings

    def generate_report(self, format: str = 'json', output_file: Optional[str] = None) -> Union[str, None]:
        """
        Generate a report of all findings.

        :param format: Report format ('json' or 'text').
        :param output_file: If specified, write report to file.
        :return: Report string or None if written to file.
        """
        if not self.findings:
            logger.info("No findings to report.")
            return "No vulnerabilities found."

        if format == 'json':
            report = json.dumps(self.findings, indent=2, default=str)
        elif format == 'text':
            lines = ["Security Scanner Report", "=" * 30]
            for i, finding in enumerate(self.findings, 1):
                lines.append(f"{i}. Type: {finding.get('type')}")
                lines.append(f"   Severity: {finding.get('severity', 'medium')}")
                lines.append(f"   Detail: {finding.get('detail')}")
                if 'file' in finding:
                    lines.append(f"   File: {finding['file']}")
                lines.append("---")
            report = "\n".join(lines)
        else:
            raise ValueError(f"Unsupported format: {format}")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(report)
            logger.info(f"Report written to {output_file}")
            return None
        return report

    # ---------- Internal methods ----------

    def _load_config(self, config_file: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load config {config_file}: {e}")
            return {}

    def _check_iam_roles(self, iam_role_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check IAM role policy for over-permissive actions.

        :param iam_role_dict: IAM role policy document.
        :return: List of findings.
        """
        findings = []
        if not iam_role_dict:
            return findings

        policy_statements = iam_role_dict.get('Statement', [])
        if not isinstance(policy_statements, list):
            policy_statements = [policy_statements]

        for statement in policy_statements:
            effect = statement.get('Effect', 'Deny').lower()
            if effect != 'allow':
                continue

            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                for over_action in self.OVER_PERMISSIVE_ACTIONS:
                    if re.match(over_action.replace('*', '.*'), action, re.IGNORECASE):
                        findings.append({
                            "type": "over-permissive-iam-role",
                            "severity": "high",
                            "detail": f"Over-permissive action '{action}' in IAM role policy"
                        })
                        break

        return findings

    def _check_vulnerable_dependencies(self, function_path: Path) -> List[Dict[str, Any]]:
        """
        Check for known vulnerable dependencies in requirements.txt or package.json.

        :param function_path: Path to function code.
        :return: List of findings.
        """
        findings = []

        # Check Python requirements.txt
        req_file = function_path / "requirements.txt"
        if req_file.exists():
            findings.extend(self._parse_requirements(req_file))

        # Check Node.js package.json
        pkg_file = function_path / "package.json"
        if pkg_file.exists():
            findings.extend(self._parse_package_json(pkg_file))

        return findings

    def _parse_requirements(self, req_file: Path) -> List[Dict[str