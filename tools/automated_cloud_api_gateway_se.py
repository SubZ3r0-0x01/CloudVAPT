import json
import sys
import logging
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urlparse

import requests

# Configure logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


class AutomatedCloudAPIGatewaySecurityAssessment:
    """
    Automated scanning and penetration testing of cloud API Gateway configurations.
    Supports AWS API Gateway, Azure API Management, and GCP API Gateway.
    Detects open endpoints, missing authentication, insecure API key handling,
    excessive permissions, and logging gaps.
    """

    # Common request ID headers used by cloud providers
    REQUEST_ID_HEADERS = [
        'x-request-id',
        'x-amzn-requestid',
        'x-ms-request-id',
        'x-correlation-id',
        'x-amz-apigw-id',
        'x-cloud-trace-context',
    ]

    # HTTP methods to test for excessive permissions
    PERMISSION_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']

    def __init__(
        self,
        provider: str,
        endpoints: Optional[List[Dict[str, Any]]] = None,
        timeout: int = 30,
        verify_ssl: bool = True,
    ):
        """
        Initialize the scanner.

        Args:
            provider: Cloud provider ('aws', 'azure', 'gcp').
            endpoints: Optional list of endpoint dictionaries. Each endpoint should have:
                - 'url': str (required)
                - 'method' (optional, default 'GET')
                - 'expected_auth_type' (optional, e.g. 'api_key', 'oauth2', 'jwt')
                - 'expected_api_key' (optional)
                - 'logging_expected' (optional bool)
            timeout: HTTP request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        if provider.lower() not in ('aws', 'azure', 'gcp'):
            raise ValueError("Provider must be one of 'aws', 'azure', 'gcp'")
        self.provider = provider.lower()
        self.endpoints = endpoints or []
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.results: List[Dict[str, Any]] = []
        self.scan_complete = False

    def add_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """
        Add an endpoint to the scan list.

        Args:
            endpoint: Dictionary with endpoint details (see __init__).
        """
        if 'url' not in endpoint:
            raise ValueError("Endpoint must contain a 'url' field")
        self.endpoints.append(endpoint)

    def load_from_json(self, filepath: str) -> None:
        """
        Load endpoints from a JSON file.

        The JSON file should contain an object or array of endpoint objects.
        If it's an object, it should have an 'endpoints' key containing the array.

        Args:
            filepath: Path to JSON file.
        """
        with open(filepath, 'r') as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get('endpoints', [])
        if isinstance(data, list):
            for ep in data:
                self.add_endpoint(ep)
        else:
            raise ValueError("JSON file must contain a list or an object with 'endpoints' key")

    def scan(self) -> List[Dict[str, Any]]:
        """
        Run all security tests on all endpoints.

        Returns:
            List of result dictionaries with findings.
        """
        self.results = []
        for endpoint in self.endpoints:
            url = endpoint.get('url')
            if not url:
                logger.warning("Skipping endpoint without URL")
                continue
            logger.info(f"Scanning endpoint: {url}")
            endpoint_result = self._scan_endpoint(endpoint)
            self.results.append(endpoint_result)
        self.scan_complete = True
        return self.results

    def _scan_endpoint(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform all security checks on a single endpoint.

        Args:
            endpoint: Endpoint dictionary.

        Returns:
            Dictionary containing findings for this endpoint.
        """
        url = endpoint['url']
        method = endpoint.get('method', 'GET').upper()
        findings = {
            'url': url,
            'method': method,
            'provider': self.provider,
            'authentication': None,
            'api_key_handling': None,
            'permissions': None,
            'logging': None,
            'errors': [],
        }

        # Test authentication
        try:
            findings['authentication'] = self._test_authentication(url, method)
        except Exception as e:
            findings['errors'].append(f"Authentication test error: {e}")

        # Test API key handling if an API key is expected
        api_key = endpoint.get('expected_api_key')
        if api_key:
            try:
                findings['api_key_handling'] = self._test_api_key_handling(
                    url, method, api_key, endpoint.get('expected_auth_type')
                )
            except Exception as e:
                findings['errors'].append(f"API key test error: {e}")
        else:
            findings['api_key_handling'] = {
                'status': 'info',
                'detail':