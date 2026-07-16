import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AutomatedKubernetesRBACAuditAndHardening:
    """
    Scans Kubernetes clusters for overly permissive RBAC configurations,
    wildcard bindings, and privilege escalations. Generates compliance reports
    aligned with CIS Kubernetes benchmarks and offers remediation guidance.
    """

    # Mapping of CIS control IDs to descriptions
    CIS_CONTROLS = {
        "CIS-5.1.1": "Avoid wildcard verbs in ClusterRole and Role definitions.",
        "CIS-5.1.2": "Avoid wildcard resources in ClusterRole and Role definitions.",
        "CIS-5.1.3": "Do not bind ClusterRole wildcards to subjects without need.",
        "CIS-5.1.4": "Audit use of cluster-admin ClusterRole binding.",
        "CIS-5.1.5": "Restrict creation of privileged containers.",
        "CIS-5.1.6": "Avoid use of system:masters group.",
        "CIS-5.1.7": "Limit access to secrets.",
        "CIS-5.1.8": "Avoid Pod impersonation and privilege escalation.",
        "CIS-5.1.9": "Audit anonymous access to RBAC.",
    }

    SEVERITY_CRITICAL = "CRITICAL"
    SEVERITY_HIGH = "HIGH"
    SEVERITY_MEDIUM = "MEDIUM"
    SEVERITY_LOW = "LOW"

    def __init__(
        self,
        api_server_url: Optional[str] = None,
        token: Optional[str] = None,
        ca_cert_path: Optional[str] = None,
        verify_ssl: bool = True,
    ):
        """
        Initialize the RBAC auditor with Kubernetes API server connection details.

        If no parameters are provided, it attempts to use the in-cluster service
        account configuration (environment variables and mounted token). Otherwise
        you must supply the API server URL and token explicitly.

        Args:
            api_server_url: Full URL to the Kubernetes API server (e.g.,
                            https://kubernetes.default.svc:443).
            token: Bearer token for authentication (service account or user token).
            ca_cert_path: Path to CA certificate file for SSL verification.
            verify_ssl: Enable/disable SSL verification. Default True.
        """
        self.api_base_url = api_server_url or self._discover_api_server()
        self.verify = ca_cert_path if ca_cert_path else verify_ssl
        self.token = token or self._load_service_account_token()
        self.headers = {"Authorization": f"Bearer {self.token}"}
        self._test_connection()

    def _discover_api_server(self) -> str:
        """Try to build the API server URL from in-cluster environment."""
        host = os.environ.get("KUBERNETES_SERVICE_HOST")
        port = os.environ.get("KUBERNETES_SERVICE_PORT")
        if host and port:
            return f"https://{host}:{port}"
        raise ValueError(
            "Cannot determine API server URL. Provide api_server_url or run in a pod "
            "with KUBERNETES_SERVICE_HOST and KUBERNETES_SERVICE_PORT set."
        )

    def _load_service_account_token(self) -> str:
        """Load service account token from the standard in-cluster path."""
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        try:
            with open(token_path, "r") as f:
                token = f.read().strip()
            if token:
                return token
        except FileNotFoundError:
            pass
        raise ValueError(
            "Cannot find authentication token. Provide token or run in a pod "
            "with a mounted service account."
        )

    def _test_connection(self) -> None:
        """Verify connectivity to the Kubernetes API server."""
        try:
            resp = self._api_request("GET", "/version")
            logger.info("Connected to Kubernetes API server %s", resp.get("gitVersion", "unknown"))
        except requests.exceptions.RequestException as e:
            logger.error("Failed to connect to API server: %s", e)
            sys.exit(1)

    def _api_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Union[Dict[str, Any], str]] = None,
    ) -> Any:
        """
        Make a request to the Kubernetes API.

        Args:
            method: HTTP method (GET, POST, etc.).
            path: API path (e.g., /apis/rbac.authorization.k8s.io/v1/clusterroles).
            params: Query parameters.
            data: JSON body or string.

        Returns:
            Parsed JSON response.

        Raises:
            requests.exceptions.RequestException on network errors.
            ValueError on non-2xx status.
        """
        url = self.api_base_url.rstrip("/") + "/" + path.lstrip("/")
        resp = requests.request(
            method,
            url,
            headers=self.headers,
            params=params,
            json=data if isinstance(data, dict) else None,
            data=data if isinstance(data, str) else None,
            verify=self.verify,
        )
        if not resp.ok:
            logger.error("API error %s: %s - %s", resp.status_code, url, resp.text)
            resp.raise_for_status()
        if resp.status_code == 204:
            return {}
        return resp.json()

    def list_namespaces(self) -> List[str]:
        """Retrieve all namespaces in the cluster."""
        items = self._api_request("GET", "/api/v1/namespaces").get("items", [])
        return [ns["metadata"]["name"] for ns in items]

    # ------------------------------------------------------------------
    # Resource retrieval
    # ------------------------------------------------------------------

    def get_cluster_roles(self) -> List[Dict[str, Any]]:
        """Return all ClusterRole objects."""
        return self._api_request("GET", "/apis/rbac.authorization.k8s.io/v1/clusterroles").get("items", [])

    def get_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        """Return all ClusterRoleBinding objects."""
        return self._api_request("GET", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings").get("items", [])

    def get_roles(self, namespace: str) -> List[Dict[str, Any]]:
        """Return all Role objects in a namespace."""
        return self._api_request(
            "GET", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{namespace}/roles"
        ).get("items", [])

    def get_role_bindings(self, namespace: str) -> List