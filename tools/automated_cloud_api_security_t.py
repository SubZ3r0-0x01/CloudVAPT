import os
import json
import time
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# Configure logging
logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


class AutomatedCloudAPISecurityTesting:
    """
    Automated Cloud API Security Testing Tool.

    This tool discovers API endpoints across AWS, Azure, and GCP,
    performs security scanning (injection, auth bypass, data exposure),
    and integrates with OWASP ZAP for comprehensive testing.

    Requires the `requests` library only. Cloud credentials are read from
    environment variables:
        - AWS: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional)
        - Azure: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
        - GCP: GCP_SERVICE_ACCOUNT_KEY (JSON string or path to key file)
    """

    def __init__(
        self,
        providers: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
        zap_base_url: Optional[str] = None,
        zap_api_key: Optional[str] = None,
        max_workers: int = 5,
    ):
        """
        Initialize the testing tool.

        :param providers: List of cloud providers to scan ('aws', 'azure', 'gcp').
                          Defaults to all supported providers.
        :param config: Additional configuration dictionary (e.g., custom headers, timeouts).
        :param zap_base_url: Base URL of OWASP ZAP API (e.g., 'http://localhost:8080').
        :param zap_api_key: API key for ZAP (if required).
        :param max_workers: Number of threads for concurrent scanning.
        """
        self.providers = providers or ['aws', 'azure', 'gcp']
        self.config = config or {}
        self.zap_base_url = zap_base_url
        self.zap_api_key = zap_api_key
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update(
            self.config.get('headers', {})
        )
        self.results: List[Dict[str, Any]] = []
        self.discovered_endpoints: List[Dict[str, Any]] = []
        # Load credentials from environment
        self._load_credentials()

    def _load_credentials(self):
        """Load cloud provider credentials from environment variables."""
        self.aws_creds = {
            'aws_access_key_id': os.environ.get('AWS_ACCESS_KEY_ID'),
            'aws_secret_access_key': os.environ.get('AWS_SECRET_ACCESS_KEY'),
            'aws_session_token': os.environ.get('AWS_SESSION_TOKEN'),
        }
        self.azure_creds = {
            'client_id': os.environ.get('AZURE_CLIENT_ID'),
            'client_secret': os.environ.get('AZURE_CLIENT_SECRET'),
            'tenant_id': os.environ.get('AZURE_TENANT_ID'),
            'subscription_id': os.environ.get('AZURE_SUBSCRIPTION_ID'),
        }
        # GCP: either a JSON string or path to key file
        gcp_key = os.environ.get('GCP_SERVICE_ACCOUNT_KEY')
        if gcp_key:
            # If it's a file path, read it
            if os.path.isfile(gcp_key):
                with open(gcp_key, 'r') as f:
                    self.gcp_creds = json.load(f)
            else:
                # Assume it's JSON string
                self.gcp_creds = json.loads(gcp_key)
        else:
            self.gcp_creds = {}

    # ------------------------------------------------------------------
    # Cloud API Discovery (AWS, Azure, GCP)
    # ------------------------------------------------------------------

    def discover_endpoints(self) -> List[Dict[str, Any]]:
        """
        Discover API endpoints from configured cloud providers.

        Returns a list of endpoint descriptions with keys:
            'url', 'method', 'provider', 'resource_id', 'auth_method', 'metadata'
        """
        logger.info("Starting endpoint discovery for providers: %s", self.providers)
        endpoints = []
        with ThreadPoolExecutor(max_workers=len(self.providers)) as executor:
            future_map = {
                executor.submit(self._discover_provider, provider): provider
                for provider in self.providers
            }
            for future in as_completed(future_map):
                provider = future_map[future]
                try:
                    provider_endpoints = future.result()
                    endpoints.extend(provider_endpoints)
                    logger.info(
                        "Discovered %d endpoints from %s",
                        len(provider_endpoints), provider
                    )
                except Exception as exc:
                    logger.error("Discovery failed for %s: %s", provider, exc)
        self.discovered_endpoints = endpoints
        return endpoints

    def _discover_provider(self, provider: str) -> List[Dict[str, Any]]:
        """Dispatch discovery to the appropriate provider method."""
        if provider == 'aws':
            return self._discover_aws()
        elif provider == 'azure':
            return self._discover_azure()
        elif provider == 'gcp':
            return self._discover_gcp()
        else:
            logger.warning("Unsupported provider: %s", provider)
            return []

    def _discover_aws(self) -> List[Dict[str, Any]]:
        """
        Discover AWS API Gateway REST APIs using the AWS API Gateway REST API.
        Requires AWS credentials (access key, secret key) with appropriate permissions.
        """
        if not all([self.aws_creds['aws_access_key_id'], self.aws_creds['aws_secret_access_key']]):
            logger.warning("AWS credentials not fully set. Skipping AWS discovery.")
            return []

        # Use the AWS API Gateway REST API to list APIs
        # Documentation: https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage.html
        # Endpoint: GET /restapis
        # We'll sign requests manually using AWS Signature V4.
        # For simplicity, we assume the environment uses Amazon's official requests
        # but we cannot import auth libraries. Instead we give an example using
        # a minimal signer or we rely on the fact that the user may have set
        # the session to use IAM roles (not possible with only requests).
        # As a pragmatic approach, we'll implement a simple AWS SigV4 signer
        # using only standard library and requests. This is complex but feasible.
        # To keep the code manageable, we'll use a helper function for signing.
        # However, in a production tool, one would use boto3. Since we are restricted,
        # we'll assume the user exports an environment variable that points to a
        # pre-signed URL or a local proxy, or we skip signing.

        # Alternatively, we can use the `aws` CLI or assume the environment has
        # a local API gateway endpoint. For the sake of providing a working example,
        # we'll simulate discovery with a placeholder.
        # In a real implementation, you would call `https://apigateway.<region>.amazonaws.com`
        # and handle signing. We'll document that.

        logger.info("AWS discovery: using provided credentials (requires SigV4 signing).")
        # Placeholder: Example using a mock API; replace with actual call.
        # Real implementation requires SigV4, which we include as a helper class.
        # We'll include a simplified version below but keep it functional.

        # For demonstration, we'll assume we can retrieve a list of API IDs from
        # the AWS API Gateway. This requires signing. We'll create a signer.
        # We'll use `aws4` library? Cannot. We'll implement basic HMAC-SHA256 signing.

        # Since this is a comprehensive example, we will implement a valid SigV4 signer
        # using standard library hashlib, hmac, etc. It is long but feasible.
        # To keep the answer concise, we can provide a stub that warns.
        # However, the requirement is to "write a complete, working Python module".
        # So I will implement a functional SigV4 signer and use it.

        # Here is a minimal AWS SigV4 implementation.
        # (Based on AWS documentation and common examples)

        import hashlib
        import hmac
        from datetime import datetime
        from urllib.parse import quote

        region = self.config.get('aws_region', 'us-east-1')
        service = 'apigateway'

        def sign_request(method: str, url: str, headers: dict, body: str = '') -> dict:
            # Simplified signing (not including all details but works for this scope)
            access_key = self.aws_creds['aws_access_key_id']
            secret_key = self.aws_creds['aws_secret_access_key']
            session_token = self.aws_creds.get('aws_session_token')

            # Parse URL
            parsed = urlparse(url)
            host = parsed.hostname
            path = parsed.path or '/'
            query_params = parsed.query

            # Create canonical request
            amz_date = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            date_stamp = datetime.utcnow().strftime('%Y%m%d')
            credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"

            headers_to_sign = {
                'host': host,
                'x-amz-date': amz_date,
            }
            if session_token:
                headers_to_sign['x-amz-security-token'] = session_token

            # Merge with existing headers
            all_headers = {**headers_to_sign, **{k.lower(): v for k, v in headers.items()}}

            # Canonical headers
            canonical_headers = ''.join(
                f"{k}:{v}\n" for k, v in sorted(all_headers.items())
            )
            signed_headers = ';'.join(sorted