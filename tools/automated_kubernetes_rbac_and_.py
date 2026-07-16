import os
import json
import logging
import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")


class AutomatedKubernetesRBACAndPodSecurityAuditingAndExploitation:
    """
    Automatically scans Kubernetes clusters for misconfigured RBAC roles, clusterroles,
    and pod security policies. It identifies overly permissive bindings,
    privilege escalation paths, and unsafe configurations, then exploits them
    to demonstrate security impact.
    """

    def __init__(
        self,
        api_server_url: Optional[str] = None,
        token: Optional[str] = None,
        verify_ssl: bool = True,
        namespace: str = "default",
        exploit: bool = False,
    ):
        """
        Initialize the scanner.

        Args:
            api_server_url: Base URL of the Kubernetes API server.
                            If None, tries to use in-cluster environment variables.
            token: Bearer token for API authentication. If None, reads from
                   /var/run/secrets/kubernetes.io/serviceaccount/token if available.
            verify_ssl: Whether to verify SSL certificates.
            namespace: Namespace to scope scanning (some resources are cluster-wide).
            exploit: If True, exploitation steps will be attempted.
        """
        self.api_server_url = api_server_url or os.getenv("KUBERNETES_SERVICE_HOST", "")
        if self.api_server_url:
            if not self.api_server_url.startswith("https://"):
                self.api_server_url = f"https://{self.api_server_url}:{os.getenv('KUBERNETES_SERVICE_PORT_HTTPS', '443')}"
        else:
            self.api_server_url = "https://kubernetes.default.svc:443"

        self.token = token
        self.verify_ssl = verify_ssl
        self.namespace = namespace
        self.exploit = exploit
        self.session = self._create_session()
        self.findings: List[Dict[str, Any]] = []
        self.exploitation_results: List[Dict[str, Any]] = []

    def _create_session(self) -> requests.Session:
        """Create a requests session with authentication from the cluster or provided token."""
        session = requests.Session()
        session.verify = self.verify_ssl

        # If token is provided, use it. Otherwise try the in-cluster service account token.
        if not self.token:
            try:
                with open("/var/run/secrets/kubernetes.io/serviceaccount/token", "r") as f:
                    self.token = f.read().strip()
            except FileNotFoundError:
                raise RuntimeError(
                    "No token provided and cannot read in-cluster service account token. "
                    "Please provide a token or run inside a pod."
                )

        session.headers.update({"Authorization": f"Bearer {self.token}"})
        # Set default content type
        session.headers.update({"Content-Type": "application/json"})
        return session

    def _api_get(self, path: str) -> requests.Response:
        """Make a GET request to the Kubernetes API."""
        url = f"{self.api_server_url}/{path.lstrip('/')}"
        logger.debug("GET %s", url)
        response = self.session.get(url)
        if response.status_code == 403:
            logger.warning("Permission denied for %s", url)
        response.raise_for_status()
        return response

    def _api_post(self, path: str, body: Dict[str, Any]) -> requests.Response:
        """Make a POST request to the Kubernetes API."""
        url = f"{self.api_server_url}/{path.lstrip('/')}"
        logger.debug("POST %s", url)
        response = self.session.post(url, json=body)
        if response.status_code == 403:
            logger.warning("Permission denied for %s", url)
        return response

    def _check_permission(self, verb: str, resource: str, name: str = "", namespace: str = "") -> bool:
        """
        Check if we have permission to perform an action using SelfSubjectAccessReview.
        This is a non‑invasive way to test without actually doing the operation.
        """
        body = {
            "apiVersion": "authorization.k8s.io/v1",
            "kind": "SelfSubjectAccessReview",
            "spec": {
                "resourceAttributes": {
                    "namespace": namespace or self.namespace,
                    "verb": verb,
                    "resource": resource,
                    "name": name,
                }
            },
        }
        try:
            resp = self._api_post("apis/authorization.k8s.io/v1/selfsubjectaccessreviews", body)
            return resp.json().get("status", {}).get("allowed", False)
        except Exception as e:
            logger.error("Failed to check permission: %s", e)
            return False

    def audit_rbac(self) -> List[Dict[str, Any]]:
        """
        Analyze RBAC resources (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings)
        for overly permissive configurations and privilege escalation paths.
        """
        logger.info("Starting RBAC audit...")
        findings = []

        # Fetch cluster-scoped resources
        try:
            clusterroles = self._api_get("apis/rbac.authorization.k8s.io/v1/clusterroles").json()
            clusterrolebindings = self._api_get("apis/rbac.authorization.k8s.io/v1/clusterrolebindings").json()
        except Exception as e:
            logger.error("Failed to fetch cluster-scoped RBAC: %s", e)
            return findings

        # Fetch namespace-scoped resources
        try:
            roles = self._api_get(f"apis/rbac.authorization.k8s.io/v1/namespaces/{self.namespace}/roles").json()
            rolebindings = self._api_get(
                f"apis/rbac.authorization.k8s.io/v1/namespaces/{self.namespace}/rolebindings"
            ).json()
        except Exception as e:
            logger.warning("Could not fetch namespace RBAC: %s", e)
            roles = {"items": []}
            rolebindings = {"items": []}

        # Check for wildcard verbs and resources in roles/clusterroles
        for role in clusterroles.get("items", []):
            name = role["metadata"]["name"]
            for rule in role.get("rules", []):
                # Check for wildcard verbs
                if "*" in rule.get("verbs", []):
                    findings.append({
                        "type": "clusterrole",
                        "name": name,
                        "issue": "Wildcard verbs (all verbs allowed)",
                        "severity": "HIGH",
                        "details": rule,
                    })
                # Check for escalation: ability to create roles/bindings
                if "create" in rule.get("verbs", []):
                    if "roles" in rule.get("resources", []) or "clusterroles" in rule.get("resources", []):
                        findings.append({
                            "type": "clusterrole",
                            "name": name,
                            "issue": "Can create roles/clusterroles (privilege escalation)",
                            "severity": "CRITICAL",
                            "details": rule,
                        })
                # Check for access to secrets or pods/exec
                if "get" in rule.get("verbs", []):
                    if "secrets" in rule.get("resources", []):
                        findings.append({
                            "type": "clusterrole",
                            "name": name,
                            "issue": "Can read secrets (potential credential access)",
                            "severity": "HIGH",
                            "details": rule,
                        })
                if "create" in rule.get("verbs", []):
                    if "pods/exec" in rule.get("resources", []):
                        findings.append({
                            "type": "clusterrole",
                            "name": name,
                            "issue": "Can exec into pods (container escape potential)",
                            "severity": "CRITICAL",
                            "details": rule,
                        })

        # Same for roles
        for role in roles.get("items", []):
            name = role["metadata"]["name"]
            for rule in role.get("rules", []):
                if "*" in rule.get("verbs", []):
                    findings.append({
                        "type": "role",
                        "namespace": self.namespace,
                        "name": name,
                        "issue": "Wildcard verbs (all verbs allowed)",
                        "severity": "HIGH",
                        "details": rule,
                    })
                if "create" in rule.get("verbs", []):
                    if "roles" in rule.get("resources", []) or "rolebindings" in rule.get("resources", []):
                        findings.append({
                            "type": "role",
                            "namespace": self.namespace,
                            "name": name,
                            "issue": "Can create roles or bindings (privilege escalation)",
                            "severity": "CRITICAL",
                            "details": rule,
                        })

        # Check clusterrolebindings for overly broad subjects
        for crb in clusterrolebindings.get("items", []):
            binding_name = crb["metadata"]["name"]
            role_ref = crb.get("roleRef", {})
            subjects = crb.get("subjects", [])

            # If binding to cluster-admin and has subjects that are not built-in users
            if role_ref.get("name") == "cluster-admin":
                for subject in subjects:
                    if subject.get("kind") in ("User", "Group", "ServiceAccount"):
                        if subject.get("name") not in ("system:masters", "system:admin"):
                            findings.append({
                                "type": "clusterrolebinding",
                                "name": binding_name,
                                "issue": f"Subject '{subject.get('name')}' is bound to cluster-admin (possibly excessive)",
                                "severity": "HIGH",
                                "details": subject,
                            })

        # Check rolebindings for potential escalations within namespace
        for rb in rolebindings.get("items", []):
            binding_name = rb["metadata"]["name"]
            role_ref = rb.get("roleRef", {})
            if role_ref.get("kind") == "ClusterRole":
                # If bound to a clusterrole like cluster-admin from within a namespace it's still dangerous
                if role_ref.get("name") == "cluster-admin":
                    subjects = rb.get("subjects", [])
                    for subject in subjects:
                        findings.append({
                            "type": "rolebinding",
                            "namespace": self.namespace,
                            "name": binding_name,
                            "issue": f"Subject '{subject.get('name')}' has cluster-admin via rolebinding (full cluster access)",
                            "severity": "CRITICAL",
                            "details": subject,
                        })

            # Check if the role itself is inside the same namespace and can escalate
            if role_ref.get("kind") == "Role":
                role_name = role_ref.get("name")
                # Find the role and check if it allows creating more roles/bindings
                for role in roles.get("items", []):
                    if role["metadata"]["name"] == role_name:
                        for rule in role.get("rules", []):