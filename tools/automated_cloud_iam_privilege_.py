import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class CloudIAMPrivilegeEscalation:
    """
    Automated Cloud IAM Privilege Escalation Detection and Exploitation.

    This class provides methods to systematically identify and exploit common IAM
    misconfigurations in AWS, Azure, and GCP that can lead to privilege escalation.
    It relies on the respective cloud CLI tools (aws, az, gcloud) being installed and
    configured.

    Attributes:
        provider (str): Cloud provider ('aws', 'azure', 'gcp').
        dry_run (bool): If True, only simulate actions; no actual changes are made.
        results (List[Dict]): Stores found vulnerabilities and exploitation results.
    """

    def __init__(self, provider: str, dry_run: bool = True) -> None:
        """
        Initialize the scanner for a given cloud provider.

        Args:
            provider: Cloud provider name ('aws', 'azure', 'gcp').
            dry_run: If True, do not perform actual exploitation, only simulate.

        Raises:
            ValueError: If provider is not supported.
        """
        if provider not in ('aws', 'azure', 'gcp'):
            raise ValueError(f"Unsupported provider: {provider}. Choose from 'aws', 'azure', 'gcp'.")
        self.provider = provider
        self.dry_run = dry_run
        self.results: List[Dict[str, Any]] = []
        self._check_cli()

    def _check_cli(self) -> None:
        """Verify that the required CLI tool is available."""
        cli_map = {
            'aws': 'aws',
            'azure': 'az',
            'gcp': 'gcloud'
        }
        cli = cli_map[self.provider]
        try:
            subprocess.run([cli, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            logger.info(f"CLI '{cli}' found.")
        except (subprocess.SubprocessError, FileNotFoundError):
            logger.error(f"Required CLI '{cli}' is not installed or not in PATH.")
            sys.exit(1)

    def _run_cli(self, command: List[str]) -> Dict[str, Any]:
        """
        Execute a CLI command and parse JSON output.

        Args:
            command: List of command arguments.

        Returns:
            Parsed JSON output as a dictionary.

        Raises:
            RuntimeError: If the command fails or JSON cannot be parsed.
        """
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, text=True)
            if result.stdout.strip():
                return json.loads(result.stdout)
            return {}
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip() if e.stderr else str(e)
            raise RuntimeError(f"CLI command failed: {' '.join(command)}\nError: {error_msg}")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse JSON output from CLI: {e}")

    def scan_for_escalations(self) -> List[Dict[str, Any]]:
        """
        Scan the cloud environment for IAM privilege escalation vulnerabilities.

        Returns:
            List of found vulnerabilities with details.
        """
        logger.info(f"Starting privilege escalation scan for {self.provider.upper()}...")
        self.results = []

        if self.provider == 'aws':
            self.results = self._scan_aws()
        elif self.provider == 'azure':
            self.results = self._scan_azure()
        elif self.provider == 'gcp':
            self.results = self._scan_gcp()

        logger.info(f"Scan completed. Found {len(self.results)} potential vulnerability(ies).")
        return self.results

    # --------------------------------------------------------------------------
    # AWS-specific scanning
    # --------------------------------------------------------------------------
    def _scan_aws(self) -> List[Dict[str, Any]]:
        """Scan AWS IAM for privilege escalation paths."""
        vulnerabilities = []
        # Fetch all users, groups, roles and their attached policies
        users = self._aws_list_users()
        for user in users:
            username = user['UserName']
            # Get inline user policies
            inline_policies = self._aws_list_user_inline_policies(username)
            for policy_name in inline_policies:
                policy_doc = self._aws_get_user_policy(username, policy_name)
                if self._aws_check_escalation_actions(policy_doc):
                    vulnerabilities.append({
                        'type': 'aws_inline_user_policy',
                        'resource': f'user/{username}',
                        'policy': policy_name,
                        'details': policy_doc,
                        'escalation_actions': self._extract_escalation_actions(policy_doc)
                    })

            # Get attached managed policies
            attached_policies = self._aws_list_user_attached_policies(username)
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_doc = self._aws_get_policy_document(policy_arn)
                if policy_doc and self._aws_check_escalation_actions(policy_doc):
                    vulnerabilities.append({
                        'type': 'aws_managed_policy',
                        'resource': f'user/{username}',
                        'policy': policy_arn,
                        'details': policy_doc,
                        'escalation_actions': self._extract_escalation_actions(policy_doc)
                    })

        # Check groups similarly (simplified for brevity - can be extended)
        groups = self._aws_list_groups()
        for group in groups:
            groupname = group['GroupName']
            attached_policies = self._aws_list_group_attached_policies(groupname)
            for policy in attached_policies:
                policy_arn = policy['PolicyArn']
                policy_doc = self._aws_get_policy_document(policy_arn)
                if policy_doc and self._aws_check_escalation_actions(policy_doc):
                    vulnerabilities.append({
                        'type': 'aws_group_managed_policy',
                        'resource': f'group/{groupname}',
                        'policy': policy_arn,
                        'details': policy_doc,
                        'escalation_actions': self._extract_escalation_actions(policy