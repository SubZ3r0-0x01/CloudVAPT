import re
import json
import os
import sys
import logging
import hashlib
import tempfile
import urllib.parse
import mimetypes
from datetime import datetime
from typing import List, Dict, Optional, Any, Union

try:
    import requests
except ImportError:
    raise ImportError("The 'requests' library is required. Install it with 'pip install requests'.")


# ----------------------------------------------------------------------
# Secret patterns used across all scanning methods
# ----------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key ID": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
    "AWS Secret Access Key": r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])",
    "Azure Storage Account Key": r"(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{88}(?![A-Za-z0-9/+])",
    "Azure SQL Connection String": r"(Server|Database|User Id|Password).*?;.*?(Server|Database|User Id|Password).*?;",
    "GCP API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GCP Service Account Private Key": r"-----BEGIN PRIVATE KEY-----[\\s\\S]*?-----END PRIVATE KEY-----",
    "GitHub Personal Access Token": r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?",
    "Password Field": r"(?i)(password|passwd|pwd)\s*[:=]\s*[\"']?[^\s\"']{8,}[\"']?",
    "Private SSH Key": r"-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
    "JWT Token": r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
    "High Entropy String (64+ chars)": r"[A-Za-z0-9+/=]{64,}",
}

# Default configuration for requests
REQUEST_TIMEOUT = 30
USER_AGENT = "AutoSecretDetector/1.0"


class AutomatedSecretsAndCredentialExposureDetection:
    """
    Automated Secrets and Credential Exposure Detection.

    Scans cloud storage services, code repositories, and container images
    for hardcoded secrets, API keys, and credentials.
    Supports AWS, Azure, and