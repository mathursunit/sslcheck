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
            "server_type": "Unknown",
            "chain": [],
            "checklist": [],
            "protocols": {},
            "security_grade": "F",
            "hsts_info": {"enabled": False, "max_age": 0},
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

            # 2. HTTP Checks (Server Type & HSTS)
            try:
                resp = requests.get(f"https://{self.hostname}", timeout=5, verify=False, allow_redirects=True)
                results["server_type"] = resp.headers.get("Server", "Unknown")
                results["checklist"].append({
                    "label": f"Server Type: {results['server_type']}",
                    "status": "success"
                })
                
                hsts = resp.headers.get("Strict-Transport-Security")
                if hsts:
                    results["hsts_info"]["enabled"] = True
                    results["checklist"].append({
                        "label": "HSTS Policy detected and active.",
                        "status": "success"
                    })
                else:
                    results["checklist"].append({
                        "label": "HSTS is not enabled.",
                        "status": "error"
                    })
            except:
                pass

            # 3. Protocol Probing
            results["protocols"] = self._probe_protocols()

            # 4. SSL Handshake & Chain Building
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(cert_bin)
                    
                    processed_fps = []
                    curr_cert = leaf_cert
                    while curr_cert and len(results["chain"]) < 5:
                        cert_data = self._parse_crypto_cert(curr_cert)
                        if cert_data["fingerprint_sha256"] in processed_fps:
                            break
                        
                        results["chain"].append(cert_data)
                        processed_fps.append(cert_data["fingerprint_sha256"])
                        
                        if curr_cert.subject == curr_cert.issuer:
                            break
                        curr_cert = self._fetch_issuer_cert(curr_cert)

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

            # Calculate Grade
            results["security_grade"] = self._calculate_grade(results)
            results["is_valid"] = all(item["status"] == "success" for item in results["checklist"] if item["label"] != "HSTS is not enabled.")
            
            return results

        except Exception as e:
            return {"error": str(e)}

    def _probe_protocols(self) -> Dict[str, bool]:
        protocols = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}
        versions = {
            "TLSv1.0": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        
        for name, version in versions.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = version
                context.maximum_version = version
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((self.hostname, self.port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        protocols[name] = True
            except:
                protocols[name] = False
        return protocols

    def _calculate_grade(self, results: Dict) -> str:
        # F: If expired or hostname mismatch (assuming these are critical fails for grade)
        for item in results["checklist"]:
            if item["status"] == "error":
                if "expire" in item["label"] or "Hostname mismatch" in item["label"]:
                    return "F"

        # F: If supporting TLS 1.0 or 1.1
        if results["protocols"].get("TLSv1.0") or results["protocols"].get("TLSv1.1"):
            return "F"
        
        # A: TLS 1.2+ only AND HSTS
        if results["hsts_info"]["enabled"] and results["protocols"].get("TLSv1.3"):
            return "A"
        
        # B: TLS 1.2+ only but no HSTS
        if not results["hsts_info"]["enabled"]:
            return "B"
            
        return "C"

    def _fetch_issuer_cert(self, cert: x509.Certificate) -> Optional[x509.Certificate]:
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for access_description in aia.value:
                if access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    url = access_description.access_location.value
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        try:
                            return x509.load_der_x509_certificate(resp.content)
                        except:
                            return None
            return None
        except:
            return None

    def _get_sans(self, cert: x509.Certificate) -> List[str]:
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return ext.value.get_values_for_type(x509.DNSName)
        except:
            cn = self._get_name_attr(cert.subject, NameOID.COMMON_NAME)
            return [cn] if cn != "Unknown" else []

    def _check_hostname(self, hostname: str, sans: List[str]) -> bool:
        for san in sans:
            clean_san = san.lower()
            clean_host = hostname.lower()
            if clean_san == clean_host: return True
            if clean_san.startswith("*."):
                suffix = clean_san[1:]
                if clean_host.endswith(suffix) and clean_host.count('.') == clean_san.count('.'):
                    return True
        return False

    def _parse_crypto_cert(self, cert: x509.Certificate) -> Dict:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint = ":".join(fingerprint[i:i+2] for i in range(0, len(fingerprint), 2))
        return {
            "common_name": self._get_name_attr(cert.subject, NameOID.COMMON_NAME),
            "organization": self._get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "issuer": self._get_name_attr(cert.issuer, NameOID.COMMON_NAME),
            "issuer_org": self._get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "serial_number": hex(cert.serial_number).upper().replace('0X', ''),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint_sha256": fingerprint,
            "sans": self._get_sans(cert)
        }

    def _get_name_attr(self, name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else "Unknown"
