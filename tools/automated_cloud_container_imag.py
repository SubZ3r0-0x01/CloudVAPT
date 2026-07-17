"""
Cloud Container Image Vulnerability Scanner module.

Provides automated vulnerability scanning for container images stored in
AWS ECR, Azure ACR, and GCP GCR using external scanners (Trivy, Grype).
Integrates into CI/CD pipelines by reporting findings and exiting non-zero
when critical vulnerabilities are