import socket
import ssl
import sys
import argparse
import json
import datetime
import logging
from urllib.parse import urlparse
import requests

class SecurityTool:
    """
    A security scanning tool for AWS environments.

    This tool performs various security scans against a target, including
    port scanning, HTTP header analysis, SSL/TLS certificate inspection,
    and checks for publicly accessible S3 buckets.

    Attributes:
        target (str): The target domain or IP address to scan.
        scan_types (list): List of scan types to perform (e.g., 'ports', 'http', 'ssl', 's3').
        timeout (int): Timeout in seconds for network operations.
        results (dict): Stores the results of the scans.
        logger (logging.Logger): Logger for the tool.
    """

    def __init__(self, target, scan_types=None, timeout=10):
        """
        Initialize the SecurityTool with a target and scan configuration.

        Args:
            target (str): The target domain or IP address.
            scan_types (list, optional): List of scan types to execute.
                Defaults to ['ports', 'http', 'ssl', 's3'].
            timeout (int, optional): Timeout for network requests. Defaults to 10.
        """
        self.target = target
        self.scan_types = scan_types if scan_types else ['ports', 'http', 'ssl', 's3']
        self.timeout = timeout
        self.results = {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

    def scan(self):
        """
        Execute the configured scans against the target.

        This method orchestrates the scanning process based on the
        specified scan_types. It populates the results dictionary with
        findings from each scan.

        Returns:
            dict: A dictionary containing the scan results.
        """
        self.logger.info(f"Starting security scan on target: {self.target}")
        self.results = {
            'target': self.target,
            'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
            'scans': {}
        }

        if 'ports' in self.scan_types:
            self.results['scans']['ports'] = self._scan_ports()
        if 'http' in self.scan_types:
            self.results['scans']['http'] = self._scan_http()
        if 'ssl' in self.scan_types:
            self.results['scans']['ssl'] = self._scan_ssl()
        if 's3' in self.scan_types:
            self.results['scans']['s3'] = self._scan_s3_bucket()

        self.logger.info("Scan completed.")
        return self.results

    def _scan_ports(self):
        """
        Perform a port scan on the target for common service ports.

        Checks for open TCP ports (21, 22, 25, 80, 443, 3306, 3389, 8080, 8443).

        Returns:
            dict: A dictionary with port numbers as keys and their status
                ('open' or 'closed') as values.
        """
        self.logger.info("Starting port scan...")
        common_ports = [21, 22, 25, 80, 443, 3306, 3389, 8080, 8443]
        port_results = {}
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                sock.close()
                if result == 0:
                    port_results[port] = 'open'
                    self.logger.debug(f"Port {port} is open")
                else:
                    port_results[port] = 'closed'
            except socket.gaierror:
                port_results[port] = 'error: hostname resolution failed'
                self.logger.error(f"Failed to resolve hostname for port scan: {self.target}")
                break
            except socket.error as e:
                port_results[port] = f'error: {e}'
                self.logger.error(f"Socket error on port {port}: {e}")
        return port_results

    def _scan_http(self):
        """
        Perform an HTTP security analysis on the target.

        Sends a GET request to the target and analyzes the response headers
        for security-relevant headers (e.g., Strict-Transport-Security,
        Content-Security-Policy, X-Frame-Options, X-Content-Type-Options).

        Returns:
            dict: A dictionary containing the HTTP status code, headers,
                and a list of missing security headers.
        """
        self.logger.info("Starting HTTP scan...")
        url = f"http://{self.target}"
        http_results = {}
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            http_results['status_code'] = response.status_code
            http_results['final_url'] = response.url
            headers = dict(response.headers)
            http_results['headers'] = headers

            # Check for security headers
            security_headers = [
                'Strict-Transport-Security',
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-Content-Type-Options',
                'X-XSS-Protection'
            ]
            missing_headers = [h for h in security_headers if h not in headers]
            http_results['missing_security_headers'] = missing_headers
            http_results['has_security_headers'] = len(missing_headers) == 0
            self.logger.debug(f"HTTP scan completed with status {response.status_code}")
        except requests.exceptions.ConnectionError:
            http_results['error'] = 'Connection failed'
            self.logger.error("HTTP scan: Connection failed")
        except requests.exceptions.Timeout:
            http_results['error'] = 'Request timed out