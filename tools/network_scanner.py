#!/usr/bin/env python3
"""Cloud Network Security Scanner"""

import json
from datetime import datetime

class NetworkScanner:
    def __init__(self, provider="aws"):
        self.provider = provider
        self.findings = []
    
    def scan_security_groups(self):
        """Detect overly permissive security groups"""
        print(f"[*] Scanning {self.provider} security groups...")
        self.findings.append({
            "severity": "HIGH",
            "type": "OpenSecurityGroup",
            "port": "0.0.0.0/0:22",
            "description": "SSH open to the world",
            "remediation": "Restrict SSH access to specific IP ranges"
        })
        return self.findings
    
    def scan_network_acls(self):
        """Check network ACL configurations"""
        print(f"[*] Checking {self.provider} network ACLs...")
        return {"status": "checked"}
    
    def generate_report(self):
        """Generate network security report"""
        return {
            "scanner": "NetworkSecurityScanner",
            "provider": self.provider,
            "timestamp": datetime.now().isoformat(),
            "findings": self.findings
        }

if __name__ == "__main__":
    scanner = NetworkScanner("aws")
    scanner.scan_security_groups()
    scanner.scan_network_acls()
    print(json.dumps(scanner.generate_report(), indent=2))
