import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Union

class KubernetesRBACPodSecurityAssessment:
    """
    Automated testing of Kubernetes RBAC configurations for least privilege violations
    and pod security policies for container escape risks. Supports EKS, AKS, GKE.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        kubeconfig_path: Optional[str] = None,
        context: Optional[str] = None,
        incluster: bool = False,
        cluster_name: Optional[str] = None,
        region: Optional[str] = None,
        resource_group: Optional[str] = None,
        project_id: Optional[str] = None,
        zone: Optional[str] = None,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
    ) -> None:
        """
        Initialize the scanner.

        :param provider: Cloud provider ('aws', 'azure', 'gcp') if using cloud CLI auth.
        :param kubeconfig_path: Path to kubeconfig file.
        :param context: Kubectl context name.
        :param incluster: Use in-cluster configuration.