import json
import time
import hashlib
import hmac
import base64
import urllib.parse
from collections import defaultdict
from typing import List, Dict, Optional, Any

import requests


class CloudAPIGatewaySecurityAssessment:
    """
    Automated Cloud API Gateway Security Assessment.

    Scans AWS API Gateway, Azure API Management, and GCP Cloud Endpoints
    for common API vulnerabilities such as injection, misconfigured authentication,
    excessive data exposure, and improper rate limiting. Also validates API endpoints
    against OWASP API Security Top 10 risks.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the scanner with optional global configuration.

        Args:
            config: Optional dictionary with default settings (e.g., timeouts, user-agent).
        """
        self.targets: List[Dict[str, Any]] = []
        self.results: List[Dict[str, Any]] = []
        self.config: Dict[str, Any] = config or {}

        # Default scanning settings
        self.config.setdefault('timeout', 10)
        self.config.setdefault('user_agent', 'CloudAPIGatewaySecurityScanner/1.0')
        self.config.setdefault('injection_payloads', [
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "<script>alert(1)</script>",
            "${7*7}",
            "| cat /etc/passwd",
        ])

    def add_target(
        self,
        provider: str,
        base_url: str,
        api_key: Optional[str] = None,
        auth_token: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None,
        rate_limit_threshold: int = 100,
    ) -> None:
        """
        Register a cloud API gateway endpoint for scanning.

        Args:
            provider: Cloud provider ('aws', 'azure', 'gcp').
            base_url: Base URL of the API (e.g., https://api.example.com).
            api_key: API key if required by the gateway.
            auth_token: Bearer token or other credentials.
            additional_headers: Custom headers to include in requests.
            rate_limit_threshold: Number of rapid requests to test rate limiting.
        """
        if provider not in ('aws', 'azure', 'gcp'):
            raise ValueError(f"Unsupported provider: {provider}")

        target = {
            'provider': provider,
            'base_url': base_url.rstrip('/'),
            'api_key': api_key,
            'auth_token': auth_token,
            'additional_headers': additional_headers or {},
            'rate_limit_threshold': rate_limit_threshold,
            'session': requests.Session(),
        }

        # Prepare default headers based on provider
        headers = target['additional_headers']
        headers.setdefault('User-Agent', self.config['user_agent'])

        if api_key:
            if provider == 'aws':
                headers['x-api-key'] = api_key
            elif provider == 'azure':
                headers['Ocp-Apim-Subscription-Key'] = api_key
            elif provider == '