import json
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IaCSecurityScanner:
    """
    Automated IaC Security Scanning class.

    Scans Terraform (.tf) and CloudFormation (JSON) templates for common security
    misconfigurations such as overly permissive IAM policies, unencrypted storage,
    and exposed security groups.

    Attributes:
        path (Path): File or directory to scan.
        recursive (bool): If True, scan directories recursively.
        cloud_providers (Optional[List[str]]): List of cloud providers to consider.
        findings (List[Dict]): Accumulated scan findings.
    """

    # ------------------------------------------------------------------
    # Pattern sets for Terraform scanning (resource type identification)
    # ------------------------------------------------------------------
    TERRAFORM_IAM_POLICY_RESOURCES: List[str] = [
        'aws_iam_policy',
        'aws_iam_role_policy',
        'aws_iam_group_policy',
        'aws_iam_user_policy',
        'aws_iam_policy_attachment',
    ]
    TERRAFORM_S3_RESOURCES: List[str] = ['aws_s3_bucket']
    TERRAFORM_SG_RESOURCES: List[str] = ['aws_security_group']

    # Pattern for effect actions
    RE_TERRAFORM_EFFECT_ALLOW = re.compile(r'effect\s*=\s*"(Allow|allow)"', re.IGNORECASE)
    RE_TERRAFORM_ACTIONS_ALL = re.compile(r'actions\s*=\s*\[?\s*"?\*"?\s*\]?', re.IGNORECASE)
    RE_TERRAFORM_PRINCIPAL_ALL = re.compile(r'principal\s*\{?\s*.*?=.*?["\']?\*["\']?\s*\}?', re.IGNORECASE)

    # S3 encryption presence check
    RE_TERRAFORM_S3_ENCRYPTION = re.compile(r'server_side_encryption_configuration', re.IGNORECASE)

    # Security group ingress check
    RE_TERRAFORM_CIDR_ALL = re.compile(r'cidr_blocks\s*=\s*\[.*?0\.0\.0\.0/0.*?\]', re.IGNORECASE)

    # ------------------------------------------------------------------
    # CloudFormation scanning helpers
    # ------------------------------------------------------------------
    CF_IAM_POLICY_RESOURCE = 'AWS::IAM::Policy'
    CF_S3_BUCKET_RESOURCE = 'AWS::S3::Bucket'
    CF_SG_RESOURCE = 'AWS::EC2::SecurityGroup'

    def __init__(
        self,
        path: str,
        recursive: bool = True,
        cloud_providers: Optional[List[str]] = None
    ) -> None:
        """
        Initialize the scanner.

        Args:
            path: Path to a file or directory to scan.
            recursive: Whether to scan directories recursively.
            cloud_providers: Optional filter for cloud providers (aws, azure, gcp).
                             If None, all providers are considered.
        """
        self.path: Path = Path(path).resolve()
        self.recursive = recursive
        self.cloud_providers = cloud_providers or ['aws', 'azure', 'gcp']
        self.find