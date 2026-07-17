import os
import json
import base64
import logging
import datetime
from typing import List, Dict, Optional, Union

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AutomatedKubernetesSecurityTesting:
    """
    Automated security assessment for Kubernetes clusters.
    Performs misconfiguration detection, RBAC analysis, secret scanning,
    container runtime auditing, and CIS benchmark checks.
    """

    def __init__(self,
                 apiserver_url: Optional[str] = None,
                 token: Optional[str] = None,
                 verify_ssl: Union[bool, str] = True,
                 ca_cert: Optional[str] = None,
                 auto_configure: bool = True):
        """
        Initialize the scanner.

        :param apiserver_url: Kubernetes API server URL (e.g., https://localhost:6443)
        :param token: Bearer token for authentication
        :param verify_ssl: Whether to verify SSL certificate. Can be bool or path to CA cert.
        :param ca_cert: Path to CA certificate file (used if verify_ssl is True and not default)
        :param auto_configure: If True and apiserver_url/token not provided, attempt in-cluster config
        """
        self.apiserver_url = apiserver_url
        self.token = token
        self.verify_ssl = verify_ssl
        self.ca_cert = ca_cert
        self.session = requests.Session()
        self.session.headers.update({'Content-Type': 'application/json'})

        # Results storage
        self.findings: List[Dict] = []
        self.scan_results: Dict = {}

        if auto_configure:
            self._auto_configure()

        if self.apiserver_url and self.token:
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})
        elif self.apiserver_url:
            logger.warning("No token provided. Some API calls may fail.")
        else:
            raise ValueError("API server URL must be provided or discovered via in-cluster config.")

        if self.ca_cert:
            self.verify_ssl = self.ca_cert

        self._test_connection()

    def _auto_configure(self):
        """Attempt to use in-cluster configuration if running inside a pod."""
        host = os.environ.get('KUBERNETES_SERVICE_HOST')
        port = os.environ.get('KUBERNETES_SERVICE_PORT')
        token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'
        ca_path = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'

        if host and port and os.path.isfile(token_path):
            if not self.apiserver_url:
                self.apiserver_url = f'https://{host}:{port}'
                logger.info("Using in-cluster API server URL: %s", self.apiserver_url)
            if not self.token:
                with open(token_path, 'r') as f:
                    self.token = f.read().strip()
                logger.info("Using in-cluster service account token.")
            if not self.ca_cert and os.path.isfile(ca_path):
                self.ca_cert = ca_path
                self.verify_ssl = ca_path
            elif not self.ca_cert:
                # In-cluster but no CA - likely custom setup, still attempt with verify True
                self.verify_ssl = True

    def _test_connection(self):
        """Verify connectivity to the API server."""
        try:
            resp = self.session.get(f'{self.apiserver_url}/api/v1', verify=self.verify_ssl, timeout=10)
            if resp.status_code == 401:
                logger.error("Authentication failed. Check token or certificate.")
                raise PermissionError("Failed to authenticate to Kubernetes API.")
            resp.raise_for_status()
            logger.info("Successfully connected to Kubernetes API server.")
        except requests.exceptions.RequestException as e:
            logger.error("Cannot reach API server: %s", e)
            raise

    def _api_request(self, path: str, method: str = 'GET', **kwargs) -> Optional[Dict]:
        """Make a Kubernetes API request with error handling."""
        url = f'{self.apiserver_url}{path}'
        try:
            resp = self.session.request(method, url, verify=self.verify_ssl,
                                        timeout=30, **kwargs)
            resp.raise_for_status()
            if resp.content:
                return resp.json()
            return None
        except requests.exceptions.HTTPError as e:
            logger.error("HTTP error %s for %s: %s", resp.status_code, path, e)
            return None
        except requests.exceptions.RequestException as e:
            logger.error("Request failed for %s: %s", path, e)
            return None

    def get_namespaces(self) -> List[str]:
        """Retrieve all namespace names."""
        data = self._api_request('/api/v1/namespaces')
        if not data:
            logger.error("Failed to list namespaces.")
            return []
        return [ns['metadata']['name'] for ns in data.get('items', [])]

    # ------------------------------------------------------------------
    # Scanning Methods
    # ------------------------------------------------------------------

    def scan_all(self) -> Dict:
        """Run all security scans and return aggregated results."""
        logger.info("Starting full Kubernetes security scan...")
        self.findings = []

        self.scan_pod_security()
        self.scan_rbac_analysis()
        self.scan_secrets()
        self.scan_container_runtime()
        self.scan_exposed_dashboards()
        self.scan_cis_benchmarks()

        self.scan_results = {
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
            'cluster_url': self.apiserver_url,
            'total_findings': len(self.findings),
            'findings': self.findings
        }
        logger.info("Scan completed. Total findings: %d", len(self.findings))
        return self.scan_results

    def scan_pod_security(self):
        """
        Check pods for insecure security contexts:
        - privileged containers
        - hostPID / hostNetwork / hostIPC
        - containers running as root
        - allowPrivilegeEscalation
        - not read-only root filesystem
        """
        logger.info("Scanning pod security contexts...")
        namespaces = self.get_namespaces()
        for ns in namespaces:
            data = self._api_request(f'/api/v1/namespaces/{ns}/pods')
            if not data:
                continue