import requests
import json
import os
import sys
import base64
import hashlib
import hmac
import datetime
import time
import re
import urllib.parse
import logging
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class AutomatedCloudWorkloadIdentityMisconfigurationDetectionAndExploitation:
    """
    Automatically identifies and exploits overly permissive trust relationships
    across cloud workload identities (IAM roles, managed identities, service accounts)
    for AWS, Azure, and GCP.
    """
    
    def __init__(self, provider: str, credentials: Optional[Dict[str, str]] = None,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize the scanner for a specific cloud provider.
        
        :param provider: Cloud provider ('aws', 'azure', 'gcp')
        :param credentials: Optional dict with authentication credentials.
            For AWS: 'access_key', 'secret_key', 'session_token' (optional)
            For Azure: 'tenant_id', 'client_id', 'client_secret' or use managed identity
            For GCP: 'service_account_json' (path or dict) or use metadata
        :param config: Optional configuration dict (e.g., region, subscription, project)
        """
        self.provider = provider.lower()
        self.credentials = credentials or {}
        self.config = config or {}
        
        # Provider-specific state
        self._aws_region = self.config.get('region', os.environ.get('AWS_DEFAULT_REGION', 'us-east-1'))
        self._azure_subscription = self.config.get('subscription',
                                                   os.environ.get('AZURE_SUBSCRIPTION_ID', ''))
        self._azure_tenant = self.credentials.get('tenant_id',
                                                  os.environ.get('AZURE_TENANT_ID', ''))
        self._gcp_project = self.config.get('project', os.environ.get('GCP_PROJECT', ''))
        
        self