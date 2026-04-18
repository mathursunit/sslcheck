import socket
import ssl
import requests
from datetime import datetime
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

class SSLChecker:
    def __init__(self, hostname: str, port: int = 443):
        self.hostname = hostname
        self.port = port

    def get_details(self) -> Dict:
        results = {
            "hostname": self.hostname,
            "ip": None,
            "server_type": None,
            "chain": [],
            "checklist": [],
            "is_valid": False,
            "errors": []
        }

        try:
            # 1. IP Resolution
            try:
                results["ip"] = socket.gethostbyname(self.hostname)
                results["checklist"].append({
                    "label": f"{self.hostname} resolves to {results['ip']}",
                    "status": "success"
                })
            except:
                results["checklist"].append({
                    "label": f"Could not resolve IP for {self.hostname}",
                    "status": "error"
                })

            # 2. Server Type (HTTP check)
            try:
                resp = requests.get(f"https://{self.hostname}", timeout=5, verify=False)
                results["server_type"] = resp.headers.get("Server", "Unknown")
                results["checklist"].append({
                    "label": f"Server Type: {results['server_type']}",
                    "status": "success"
                })
            except:
                pass

            # 3. SSL Handshake & Certificate
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(cert_bin)
                    
                    # Process Leaf
                    leaf_data = self._parse_crypto_cert(leaf_cert)
                    results["chain"].append(leaf_data)
                    
                    # Checklist: Expiry
                    days_left = (leaf_cert.not_valid_after - datetime.utcnow()).days
                    if days_left > 0:
                        results["checklist"].append({
                            "label": f"The certificate will expire in {days_left} days.",
                            "status": "success"
                        })
                    else:
                        results["checklist"].append({
                            "label": f"The certificate has expired ({abs(days_left)} days ago).",
                            "status": "error"
                        })

                    # Checklist: Hostname match
                    san_list = self._get_sans(leaf_cert)
                    if self._check_hostname(self.hostname, san_list):
                        results["checklist"].append({
                            "label": f"The hostname ({self.hostname}) is correctly listed in the certificate.",
                            "status": "success"
                        })
                    else:
                        results["checklist"].append({
                            "label": f"Hostname mismatch: {self.hostname} not found in SANs.",
                            "status": "error"
                        })

            results["is_valid"] = all(item["status"] == "success" for item in results["checklist"])
            return results

        except Exception as e:
            return {"error": str(e)}

    def _get_sans(self, cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return ext.value.get_values_for_type(x509.DNSName)
        except:
            return []

    def _check_hostname(self, hostname: str, sans: List[str]) -> bool:
        for san in sans:
            if san == hostname:
                return True
            if san.startswith("*."):
                suffix = san[1:]
                if hostname.endswith(suffix) and hostname.count('.') == san.count('.'):
                    return True
        return False

    def _parse_crypto_cert(self, cert: x509.Certificate) -> Dict:
        def name_to_str(name):
            components = []
            for attr in name:
                components.append(f"{attr.oid._name}={attr.value}")
            return ", ".join(components)

        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))

        # Get SANs if available
        sans = self._get_sans(cert)

        return {
            "common_name": self._get_name_attr(cert.subject, NameOID.COMMON_NAME),
            "issuer": self._get_name_attr(cert.issuer, NameOID.COMMON_NAME),
            "issuer_full": name_to_str(cert.issuer),
            "subject_full": name_to_str(cert.subject),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "serial_number": hex(cert.serial_number).upper().replace('0X', ''),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint_sha256": fingerprint,
            "sans": sans
        }

    def _get_name_attr(self, name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else "Unknown"
