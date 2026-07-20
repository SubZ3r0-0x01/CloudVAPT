import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

import requests

# -----------------------------------------------------------------------------
# Module-level logger
# -----------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(_handler)


class ContainerSecurityAssessment:
    """
    Automated tool to assess security posture of Docker containers and
    Kubernetes clusters.

    Capabilities:
        - Scan container images for vulnerabilities (via Docker Scout / Docker Scan).
        - Analyse Dockerfile compliance with best practices.
        - Evaluate Kubernetes configurations against common CIS benchmarks and
          security best practices.

    Dependencies:
        - Python 3.8+
        - `requests` library (for optional external vulnerability lookups)
        - Docker CLI (`docker`, `docker scout` or `docker scan` for vuln. scanning)
        - `kubectl` (for Kubernetes cluster scanning)
    """

    # -------------------------------------------------------------------------
    # Dockerfile check rules (regular expressions or string patterns)
    # -------------------------------------------------------------------------
    DOCKERFILE_RULES = {
        "avoid_root_user": {
            "pattern": r"^USER\s+root\s*$",
            "severity": "HIGH",
            "advice": "Avoid running containers as root. Create a dedicated user."
        },
        "pin_base_image_version": {
            "pattern": r"^FROM\s+\S+:\S+@sha256:[a-f0-9]{64}",
            "severity": "MEDIUM",
            "advice": "Pin base image digest to ensure immutability."
        },
        "no_latest_tag": {
            "pattern": r"^FROM\s+\S+:\s*latest\s*$",
            "severity": "HIGH",
            "advice": "Avoid using the 'latest' tag. Use a specific version."
        },
        "explicit_package_manager_update": {
            "pattern": r"^\s*(RUN\s+(apt-get|apk|yum|dnf|zypper)\s+update)",
            "severity": "LOW",
            "advice": "Consider combining update and install in one RUN to reduce layer size."
        },
        "avoid_sudo": {
            "pattern": r"\bsudo\b",
            "severity": "HIGH",
            "advice": "Avoid using sudo inside containers. Use USER instruction instead."
        },
        "use_copy_instead_of_add": {
            "pattern": r"^\s*ADD\s+",
            "severity": "MEDIUM",
            "advice": "Prefer COPY over ADD unless you need remote URL or tar extraction."
        },
        "set_healthcheck": {
            "pattern": r"^\s*HEALTHCHECK\s+",
            "severity": "LOW",
            "advice": "Add a HEALTHCHECK instruction to enable container health monitoring."
        },
        "no_raw_credentials": {
            "pattern": r"(PASSWORD|SECRET|API_KEY|TOKEN)\s*=",
            "severity": "CRITICAL",
            "advice": "Never embed credentials in Docker