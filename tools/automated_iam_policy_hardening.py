#!/usr/bin/env python3
"""
Automated IAM Policy Hardening and Anomaly Detection

Scans AWS, Azure, and GCP IAM configurations to identify over-privileged roles,
risky trust policies, and unused permissions. Provides actionable recommendations
to enforce least-privilege access across cloud environments.

Usage:
    python -m iam_hardening_scanner [--providers aws,azure,gcp] [--format text|json]

Dependencies:
    - Python standard library
    - requests
"""

import os
import json
import sys
import datetime
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlencode

import base64
import hashlib
import hmac
import re
import textwrap

try:
    import requests
except ImportError:
    print("This module requires 'requests'. Install it with: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------
class IAMScannerError(Exception):
    """Base exception for IAM scanner errors."""


class ProviderAuthError(IAMScannerError):
    """Raised when authentication with a cloud provider fails."""


class ProviderApiError(IAMScannerError):
    """Raised when a cloud provider API returns an error."""


# ---------------------------------------------------------------------------
# AWS Signature V4 signing (only standard lib + requests)
# ---------------------------------------------------------------------------
def _aws_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _aws_hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _aws_get_signature_key(key: bytes, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _aws_hmac_sha256(b"AWS4" + key, date_stamp.encode('utf-8'))
    k_region = _aws_hmac_sha256(k_date, region.encode('utf-8'))
    k_service = _aws_hmac_sha256(k_region, service.encode('utf-8'))
    k_signing = _aws_hmac_sha256(k_service, b"aws4_request")
    return k_signing


def _aws_sign_v4_post(
    access_key: str,
    secret_key: str,
    region: str,
    service: str,
    host: str,
    canonical_uri: str,
    query_string: str,
    payload: str,
    session_token: Optional[str] = None,
) -> Dict[str, str]:
    """Sign an HTTP POST request with AWS Signature V4 and return headers."""
    now = datetime.datetime.utcnow()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")  # Date w/o time for key generation

    # ************* TASK 1: CREATE CANONICAL REQUEST *************
    method = "POST"
    canonical_headers = (
        f"content