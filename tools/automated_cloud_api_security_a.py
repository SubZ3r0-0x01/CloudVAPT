import logging
import sys
import json
import time
import random
import string
from urllib.parse import urljoin, urlparse
from collections import defaultdict

import requests

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger('AutomatedCloudAPISecurityAssessment')


class AutomatedCloudAPISecurityAssessment:
    """
    A tool to scan and test cloud API gateway endpoints and serverless functions
    for vulnerabilities based on the OWASP API Security Top 10.

    This class performs automated discovery, authentication testing, injection checks,
    and mass assignment analysis to identify misconfigurations and security weaknesses
    in cloud-native APIs.

    Supported cloud providers: AWS, Azure, GCP
    """

    # Common API discovery paths for cloud providers
    COMMON_ENDPOINTS = {
        'aws': [
            '/api', '/v1', '/v2', '/prod', '/stage', '/latest',
            '/users', '/items', '/data', '/health', '/status',
            '/.well-known/openid-configuration'
        ],
        'azure': [
            '/api', '/v1', '/v2', '/prod', '/function', '/api/health',
            '/swagger.json', '/.well-known/openid-configuration'
        ],
        'gcp': [
            '/api', '/v1', '/v2', '/endpoints', '/cloudfunctions',
            '/health', '/status', '/.well-known/openid-configuration'
        ]
    }

    # Common injection payloads for testing
    INJECTION_PAYLOADS = {
        'sql': [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "1; SELECT * FROM admin",
            "admin' --",
            "admin' /*",
            "' OR 1=1--",
            "' OR '1'='1' --",
            "' OR '1'='1' #"
        ],
        'command': [
            "; ls",
            "| dir",
            "&& whoami",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "'; cat /etc/passwd",
            "| cat /etc/passwd",
            "&& cat /etc/passwd",
            "|| cat /etc/passwd",
            "; cat /etc/passwd"
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
            "....//....//....//etc/passwd"
        ]
    }

    # Common mass assignment fields to test
    MASS_ASSIGNMENT_FIELDS = [
        'is_admin', 'admin', 'role', 'roles', 'permissions', 'privileges',
        'is_active', 'is_verified', 'is_premium', 'account_type', 'user_type',
        'is_superuser', 'is_staff', 'is_owner', 'access_level', 'level'
    ]

    def __init__(self, cloud_provider, base_url=None, endpoints=None, api_key=None,
                 auth_token=None, timeout=10, verify_ssl=True, max_retries=3,
                 proxy=None, user_agent=None):
        """
        Initialize the scanner with configuration.

        Args:
            cloud_provider (str): Cloud provider type ('aws', 'azure', 'gcp')
            base_url (str, optional): Base URL of the API gateway
            endpoints (list, optional): Specific endpoints to test
            api_key (str, optional): API key for authentication
            auth_token (str, optional): Bearer token for authentication
            timeout (int, optional): Request timeout in seconds (default: 10)
            verify_ssl (bool, optional): Verify SSL certificates (default: True)
            max_retries (int, optional): Maximum retries for failed requests (default: 3)
            proxy (dict, optional): Proxy configuration
            user_agent (str, optional): Custom User-Agent string
        """
        self.cloud_provider = cloud_provider.lower()
        if self.cloud_provider not in ['aws', 'azure', 'gcp']:
            raise ValueError(f"Unsupported cloud provider: {cloud_provider}. "
                             f"Supported providers: aws, azure, gcp")

        self.base_url = base_url.rstrip('/') if base_url else None
        self.endpoints = endpoints or []
        self.api_key = api_key
        self.auth_token = auth_token
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.proxy = proxy
        self.user_agent = user_agent or 'AutomatedCloudAPISecurityAssessment/1.0'

        # Store scan results
        self.scan_results = {
            'discovery': [],
            'authentication': [],
            'injection': [],
            'mass_assignment': [],
            'summary': {}
        }

        # Session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json'
        })
        if self.api_key:
            self.session.headers.update({'X-API-Key': self.api_key})
        if self.auth_token:
            self.session.headers.update({'Authorization': f'Bearer {self.auth_token}'})
        if self.proxy:
            self.session.proxies.update(self.proxy)

        logger.info(f"Initialized scanner for {self.cloud_provider.upper()}")

    def _make_request(self, method, url, **kwargs):
        """
        Make an HTTP request with retry logic.

        Args:
            method (str): HTTP method (GET, POST, PUT, DELETE, etc.)
            url (str): Full URL
            **kwargs: Additional arguments for requests.request

        Returns:
            requests.Response or None: Response object or None on failure
        """
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)

        for attempt in range(1, self.max_retries + 1):
            try:
                logger.debug(f"Request: {method} {url} (attempt {attempt})")
                response = self.session.request(method, url, **kwargs)
                logger.debug(f"Response: {response.status_code}")
                return response
            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on {method} {url} (attempt {attempt})")
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff
            except requests.exceptions.ConnectionError as e:
                logger.error(f"Connection error on {method} {url}: {e}")
                break
            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed on {method} {url}: {e}")
                break
        return None

    def discover_endpoints(self, base_url=None):
        """
        Discover API endpoints by probing common paths.

        This method tests a list of common API paths (based on the cloud provider)
        against the base URL to discover available endpoints.

        Args:
            base_url (str, optional): Base URL to probe. Defaults to self.base_url.

        Returns:
            list: List of discovered endpoint URLs
        """
        base = base_url or self.base_url
        if not base:
            logger.error("No base URL provided for endpoint discovery")
            return []

        logger.info(f"Starting endpoint discovery on {base}")
        discovered = []

        # Get common paths for the cloud provider
        paths = self.COMMON_ENDPOINTS.get(self.cloud_provider, [])
        if not paths:
            logger.warning(f"No common endpoints defined for {self.cloud_provider}")
            return []

        for path in paths:
            url = urljoin(base, path)
            response = self._make_request('GET', url)

            if response and response.status_code < 500:
                # Consider any non-5xx response as a potential endpoint
                discovered.append({
                    'url': url,
                    'method': 'GET',
                    'status_code': response.status_code,
                    'content_type': response.headers.get('Content-Type', ''),
                    'size': len(response.content)
                })
                logger.info(f"Discovered endpoint: {url} (status: {response.status_code})")

        self.scan_results['discovery'] = discovered
        logger.info(f"Discovery complete. Found {len(discovered)} endpoints.")
        return discovered

    def test_authentication(self, endpoints=None):
        """
        Test authentication mechanisms for common vulnerabilities.

        Checks for:
        - Missing authentication headers
        - Weak or predictable tokens
        - Bypass via HTTP method manipulation
        - Bypass via path manipulation
        - Insecure direct object references (IDOR) via token validation

        Args:
            endpoints (list, optional): List of endpoint dictionaries. Defaults to discovered endpoints.

        Returns:
            list: List of findings with details
        """
        endpoints_to_test = endpoints or self.scan_results.get('discovery', self.endpoints)
        if not endpoints_to_test:
            logger.warning("No endpoints provided for authentication testing")
            return []

        logger.info("Starting authentication testing")
        findings = []

        # Ensure we have endpoints in dict format
        if isinstance(endpoints_to_test[0], str):
            endpoints_to_test = [{'url': e, 'method': 'GET'} for e in endpoints_to_test]

        for endpoint in endpoints_to_test:
            url = endpoint['url']
            method = endpoint.get('method', 'GET').upper()

            # Test 1: Missing authentication
            logger.debug(f"Testing missing auth on {url}")
            response = self._make_request(method, url)
            if response and