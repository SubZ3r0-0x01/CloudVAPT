import json
import os
import sys
import datetime
import hmac
import hashlib
import base64
import urllib.parse
import textwrap
import requests
from typing import Dict, List, Any


class AutoCloudDbSecurityAssessment:
    """
    Automated Cloud Database Security Assessment

    Scans cloud database services (AWS RDS, Azure SQL Database, GCP Cloud SQL)
    for common misconfigurations and provides remediation steps.
    """

    def __init__(self, cloud_provider: str, credentials: Dict[str, str],
                 region: str = None, subscription_id: str = None,
                 project_id: str = None):
        """
        Initialize the scanner.

        Args:
            cloud_provider: 'aws', 'azure', or 'gcp'
            credentials: dictionary with provider-specific keys
                - For AWS: 'aws_access_key_id', 'aws_secret_access_key',
                  optional 'aws_session_token'
                - For Azure: 'azure_subscription_id', 'azure_access_token'
                - For GCP: 'gcp_project_id', 'gcp_access_token' or
                  'gcp_service_account_file'
            region: AWS region (required for AWS)
            subscription_id: Azure subscription ID (alternative to credentials)
            project_id: GCP project ID (alternative to credentials)
        """
        self.cloud_provider = cloud_provider.lower()
        self.credentials = credentials
        self.region = region or credentials.get('region')
        self.subscription_id = subscription_id or credentials.get(
            'azure_subscription_id')
        self.project_id = project_id or credentials.get('gcp_project_id')
        self.findings = []

    def scan(self) -> List[Dict[str, Any]]:
        """
        Run the security scan for the configured cloud provider.

        Returns:
            List of findings, each a dict with 'resource', 'issue',
            'severity', 'remediation'.
        """
        if self.cloud_provider == 'aws':
            self._scan_aws()
        elif self.cloud_provider == 'azure':
            self._scan_azure()
        elif self.cloud_provider == 'gcp':
            self._scan_gcp()
        else:
            raise ValueError(f"Unsupported cloud provider: {self.cloud_provider}")
        return self.findings

    def _scan_aws(self):
        """
        Scan AWS RDS instances for misconfigurations using the RDS API.
        Required credentials: aws_access_key_id, aws_secret_access_key
        Required region: set in __init__ or credentials dict.
        """
        if not self.region:
            raise ValueError("region is required for AWS scanning")
        access_key = self.credentials.get('aws_access_key_id')
        secret_key = self.credentials.get('aws_secret_access_key')
        session_token = self.credentials.get('aws_session_token')
        if not access_key or not secret_key:
            raise ValueError("AWS credentials (aws_access_key_id and "
                             "aws_secret_access_key) required")

        # Prepare request to DescribeDBInstances
        method = 'GET'
        service = 'rds'
        host = f'rds.{self.region}.amazonaws.com'
        endpoint = f'https://{host}/'
        params = {'Action': 'DescribeDBInstances', 'Version': '2014-10-31'}
        headers = {'Host': host}
        if session_token:
            headers['X-Amz-Security-Token'] = session_token

        # Sign request
        signed_headers = self._sign_aws_request(
            method, service, host, endpoint, params, headers,
            access_key, secret_key, session_token, self.region
        )

        response = requests.get(endpoint, params=params, headers=signed_headers,
                                timeout=30)
        if response.status_code != 200:
            error_msg = f"AWS API error {response.status_code}: {response.text}"
            print(error_msg, file=sys.stderr)
            self.findings.append({
                'resource': 'AWS RDS API',
                'issue': f'Failed to fetch instances: {error_msg}',
                'severity': 'HIGH',
                'remediation': 'Check credentials, permissions, and network.'
            })
            return

        data = response.json()
        instances = data.get('DescribeDBInstancesResponse', {}).get(
            'DescribeDBInstancesResult', {}).get('DBInstances', [])
        for db in instances:
            db_id = db.get('DBInstanceIdentifier', 'unknown')
            # Check public accessibility
            if db.get('PubliclyAccessible', False):
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': 'Database is publicly accessible',
                    'severity': 'CRITICAL',
                    'remediation': 'Set PubliclyAccessible to False and '
                                   'restrict security group inbound rules.'
                })
            # Check encryption at rest
            if not db.get('StorageEncrypted', False):
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': 'Storage encryption is disabled',
                    'severity': 'HIGH',
                    'remediation': 'Enable encryption at rest using '
                                   'AWS KMS. Modify the instance to '
                                   'enable encryption (may require snapshot).'
                })
            # Check backup retention
            backup_retention = db.get('BackupRetentionPeriod', 0)
            if backup_retention < 7:
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': f'Backup retention period is {backup_retention} days '
                             '(recommended >= 7)',
                    'severity': 'MEDIUM',
                    'remediation': 'Increase BackupRetentionPeriod to at least 7 '
                                   'days for point-in-time recovery.'
                })
            # Check master username / password authentication strength? Not directly
            # Check if instance is in a VPC (not classic)
            if not db.get('DBSubnetGroup', {}).get('VpcId'):
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': 'Instance is not in a VPC (EC2-Classic)',
                    'severity': 'HIGH',
                    'remediation': 'Migrate to VPC to use security groups and '
                                   'network isolation.'
                })
            # Check minor version upgrade
            if db.get('AutoMinorVersionUpgrade', False) is False:
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': 'Auto minor version upgrade disabled',
                    'severity': 'LOW',
                    'remediation': 'Enable AutoMinorVersionUpgrade to receive '
                                   'automated security patches.'
                })
            # Check deletion protection
            if not db.get('DeletionProtection', False):
                self.findings.append({
                    'resource': f'RDS Instance {db_id}',
                    'issue': 'Deletion protection is disabled',
                    'severity': 'MEDIUM',
                    'remediation': 'Enable DeletionProtection to prevent '
                                   'accidental deletion.'
                })
            # Check if multi-AZ for high availability (not strictly security)
            # Check if inbound traffic from 0.0.0.0/0 is allowed? Would need
            # security group info, not in this response.

    def _sign_aws_request(self, method, service, host, endpoint, params,
                          headers, access_key, secret_key, session_token,
                          region):
        """Sign an AWS API request using Signature V4."""
        algorithm = 'AWS4-HMAC-SHA256'
        amz_date = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        date_stamp = amz_date[:8]
        headers['X-Amz-Date'] = amz_date
        if session_token:
            headers['X-Amz-Security-Token'] = session_token

        # 1. Create canonical request
        # Canonical URI
        canonical_uri = '/'
        # Canonical query string
        sorted_params = sorted(params.items())
        canonical_querystring = '&'.join(
            [f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
             for k, v in sorted_params]
        )
        # Canonical headers
        header_keys = sorted(headers.keys())
        canonical_headers = '\n'.join(
            [f'{k.lower()}:{headers[k]}' for k in header_keys]
        ) + '\n'
        signed_headers = ';'.join([k.lower() for k in header_keys])

        # Payload hash (for GET request empty body, SHA256 of empty string)
        payload_hash = hashlib.sha256('