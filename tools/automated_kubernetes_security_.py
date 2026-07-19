import os
import sys
import json
import ssl
import base64
import logging
import socket
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse

import requests

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class AutomatedKubernetesSecurityAssessment:
    """
    Automated Kubernetes Security Assessment tool.

    Scans Kubernetes clusters for common security weaknesses including:
    - Misconfigured RBAC (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings)
    - Exposed dashboards (Kubernetes Dashboard, custom dashboards)
    - Insecure Pod Security Policies
    - Network policy gaps

    Supports AWS EKS, Azure AKS, GCP GKE and any standard Kubernetes cluster
    accessible via the Kubernetes API.

    Authentication is supported via:
    - In-cluster service account (when running inside a pod)
    - Direct API token and CA certificate
    - kubeconfig file (requires `kubectl` in PATH)

    Dependencies:
        - Python 3.6+
        - requests library (must be installed separately)
        - kubectl (optional, only needed for kubeconfig loading)

    Usage:
        # In-cluster
        scanner = AutomatedKubernetesSecurityAssessment()
        scanner.connect()
        scanner.scan_all()
        scanner.generate_report('report.json')

        # Via token
        scanner = AutomatedKubernetesSecurityAssessment(
            host='https://api.example.com:6443',
            token='your-token',
            ca_cert='/path/to/ca.crt'
        )
        scanner.connect()
        scanner.scan_all()
        scanner.generate_report()
    """

    def __init__(
        self,
        host: Optional[str] = None,
        token: Optional[str] = None,
        ca_cert: Optional[str] = None,
        kubeconfig: Optional[str] = None,
        context: Optional[str] = None,
        insecure_skip_tls_verify: bool = False,
        timeout: int = 30,
        user_agent: str = 'K8sSecurityScanner/1.0'
    ):
        """
        Initialize the scanner.

        Args:
            host: Kubernetes API server URL (e.g., https://example.com:6443).
            token: Bearer token for API authentication.
            ca_cert: Path to CA certificate file.
            kubeconfig: Path to kubeconfig file (requires kubectl).
            context: Context to use from kubeconfig.
            insecure_skip_tls_verify: Skip TLS verification (not recommended).
            timeout: HTTP request timeout in seconds.
            user_agent: User-Agent header to use.
        """
        self.host = host
        self.token = token
        self.ca_cert = ca_cert
        self.kubeconfig = kubeconfig
        self.context = context
        self.insecure_skip_tls_verify = insecure_skip_tls_verify
        self.timeout = timeout
        self.user_agent = user_agent

        self.session: Optional[requests.Session] = None
        self.api_url: Optional[str] = None
        self._connected: bool = False
        self.scan_results: Dict[str, Any] = {}
        self.server_version: Optional[str] = None
        self.cluster_name: Optional[str] = None

    # ------------------------------------------------------------------
    # Connection / Authentication
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """
        Establish connection to the Kubernetes API server.

        Configures authentication from the provided parameters or falls back
        to in-cluster environment variables and service account token.
        """
        if self._connected and self.session:
            return

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user