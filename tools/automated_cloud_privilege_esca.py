import os
import sys
import json
import logging
import time
import urllib.parse
import hashlib
import hmac
import base64
import uuid
from datetime import datetime, timezone

import requests


class CloudPrivilegeEscalationPathDiscovery:
    """
    Automated scanner for cloud privilege escalation paths across AWS, Azure, and GCP.
    """

    def __init__(self, config=None):
        """
        Initialize the scanner with an optional configuration dictionary.
        """
        self.config = config or {}
        self.results = {
            'aws': {},
            'azure': {},
            'gcp': {},
            'summary': {}
        }
        self.logger = logging.getLogger(self.__class__.__name__)
        self._configure_logging()

    def _configure_logging(self, level=None):
        """Set up logging for the scanner."""
        log_level = level or self.config.get('log_level', logging.INFO)
        self.logger.setLevel(log_level)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '[%(asctime)s] %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    # ----------------------------------------------------------------------
    # AWS SigV4 signing (using only standard library + requests)
    # ----------------------------------------------------------------------
    @staticmethod
    def _aws_sha256(data):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    @staticmethod
    def _aws_hmac_sha256(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

    def _aws_get_signature_key(self, key, date_stamp, region, service):
        k_date = self._aws_hmac_sha256(('AWS4' + key).encode('utf-8'), date_stamp)
        k_region = self._aws_hmac_sha256(k_date, region)
        k_service = self._aws_hmac_sha256(k_region, service)
        k_signing = self._aws_hmac_sha256(k_service, 'aws4_request')
        return k_signing

    def _aws_sign_request(self, method, service, region, path, params=None,
                         headers=None, payload='', access_key='', secret_key='',
                         token=None):
        """Sign and execute an AWS API request (SigV4)."""
        if params is None:
            params = {}
        if headers is None:
            headers = {}
        # Prepare basic headers
        amz_date = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        date_stamp = amz_date[:8]
        headers['Host'] = f'{service}.{region}.amazonaws.com'
        headers['X-Amz-Date'] = amz_date
        if token:
            headers['X-Amz-Security-Token'] = token

        # Canonical request
        canonical_uri = path if path.startswith('/') else '/' + path
        canonical_querystring = '&'.join(
            f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
            for k, v in sorted(params.items())
        )
        payload_hash = self._aws_sha256(payload)
        canonical_headers = ''.join(
            f'{k.lower()}:{v.strip()}\n' for k, v in sorted(headers.items())
        )
        signed_headers = ';'.join(sorted(headers.keys()))
        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\n{payload_hash}"
        )

        # String to sign
        algorithm = 'AWS4-HMAC-SHA256'
        credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
        string_to_sign = (
            f"{algorithm}\n{amz_date}\n{credential_scope}\n"
            f"{self._aws_sha256(canonical_request)}"
        )

        # Calculate signature
        signing_key = self._aws_get_signature_key(secret_key, date_stamp, region, service)
        signature = hmac.new(signing_key, string_to_sign.encode('utf-8'),
                            hashlib.sha256).hexdigest()

        # Add authorization header
        authorization = (
            f"{algorithm} Credential={access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature