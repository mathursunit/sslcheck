import socket
import ssl
import requests
import time
from datetime import datetime
from typing import List, Dict, Optional
import dns.resolver
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
            "cipher_info": {"name": "Unknown", "bits": 0, "strength": "Weak"},
            "handshake_time": 0,
            "alpn": "None",
            "security_grade": "F",
            "hsts_info": {"enabled": False, "preloaded": False},
            "caa_data": {"exists": False, "records": []},
            "is_valid": False,
            "errors": []
        }

        try:
            # 1. IP & DNS (CAA Check)
            try:
                results["ip"] = socket.gethostbyname(self.hostname)
                results["checklist"].append({"label": f"{self.hostname} resolves to {results['ip']}", "status": "success"})
            except:
                results["checklist"].append({"label": f"Could not resolve IP for {self.hostname}", "status": "error"})

            self._check_caa(results)

            # 2. HTTP Checks
            self._check_hsts(results)

            # 3. Protocol & Handshake Depth
            start_time = time.time()
            context = ssl.create_default_context()
            context.set_alpn_protocols(['h2', 'http/1.1'])
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    results["handshake_time"] = round((time.time() - start_time) * 1000, 2)
                    cipher = ssock.cipher()
                    results["cipher_info"] = {
                        "name": cipher[0],
                        "bits": cipher[2],
                        "strength": "Strong" if cipher[2] >= 256 else "Secure" if cipher[2] >= 128 else "Weak"
                    }
                    results["alpn"] = ssock.selected_alpn_protocol() or "http/1.1"
                    
                    # Process Certs
                    cert_bin = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(cert_bin)
                    self._process_chain(leaf_cert, results)

                    # Checklist basics
                    self._run_checklist_basics(leaf_cert, results)

            # 4. Global Protocol Probing
            results["protocols"] = self._probe_protocols()

            # 5. Final Grading
            results["security_grade"] = self._calculate_grade(results)
            results["is_valid"] = all(item["status"] == "success" for item in results["checklist"] if "HSTS" not in item["label"])
            
            return results

        except Exception as e:
            return {"error": str(e)}

    def _check_caa(self, results):
        try:
            answers = dns.resolver.resolve(self.hostname, 'CAA')
            for rdata in answers:
                results["caa_data"]["records"].append(str(rdata))
            results["caa_data"]["exists"] = len(results["caa_data"]["records"]) > 0
            if results["caa_data"]["exists"]:
                results["checklist"].append({"label": "CAA security policy detected.", "status": "success"})
            else:
                results["checklist"].append({"label": "No CAA policy found (optional but recommended).", "status": "info"})
        except:
            pass

    def _check_hsts(self, results):
        try:
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            resp = requests.get(f"https://{self.hostname}", timeout=5, verify=False, allow_redirects=True, headers=headers)
            results["server_type"] = resp.headers.get("Server", "Unknown")
            hsts = resp.headers.get("Strict-Transport-Security")
            if hsts:
                results["hsts_info"]["enabled"] = True
                results["checklist"].append({"label": "HSTS Policy detected.", "status": "success"})
            else:
                p_resp = requests.get(f"https://hstspreload.org/api/v2/status?domain={self.hostname}", timeout=3)
                if p_resp.status_code == 200 and p_resp.json().get("status") == "preloaded":
                    results["hsts_info"]["enabled"] = True
                    results["hsts_info"]["preloaded"] = True
                    results["checklist"].append({"label": "HSTS enabled via Browser Preload List.", "status": "success"})
            
            if not results["hsts_info"]["enabled"]:
                results["checklist"].append({"label": "HSTS is not enabled.", "status": "error"})
        except: pass

    def _probe_protocols(self) -> Dict[str, bool]:
        protocols = {"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}
        versions = {"TLSv1.0": ssl.TLSVersion.TLSv1, "TLSv1.1": ssl.TLSVersion.TLSv1_1, "TLSv1.2": ssl.TLSVersion.TLSv1_2, "TLSv1.3": ssl.TLSVersion.TLSv1_3}
        for name, ver in versions.items():
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ver
                context.maximum_version = ver
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.hostname, self.port), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as _:
                        protocols[name] = True
            except: pass
        return protocols

    def _calculate_grade(self, results: Dict) -> str:
        failed_crit = any(i["status"] == "error" and ("expire" in i["label"] or "Hostname mismatch" in i["label"]) for i in results["checklist"])
        if failed_crit or results["protocols"].get("TLSv1.0") or results["protocols"].get("TLSv1.1"): return "F"
        
        has_hsts = results["hsts_info"]["enabled"]
        has_tls13 = results["protocols"].get("TLSv1.3")
        is_strong = results["cipher_info"]["strength"] == "Strong"
        
        if has_hsts and has_tls13 and is_strong: return "A"
        if has_hsts or has_tls13: return "B"
        return "C"

    def _process_chain(self, leaf, results):
        processed_fps = []
        curr_cert = leaf
        while curr_cert and len(results["chain"]) < 5:
            data = self._parse_crypto_cert(curr_cert)
            if data["fingerprint_sha256"] in processed_fps: break
            results["chain"].append(data)
            processed_fps.append(data["fingerprint_sha256"])
            if curr_cert.subject == curr_cert.issuer: break
            curr_cert = self._fetch_issuer_cert(curr_cert)

    def _fetch_issuer_cert(self, cert):
        try:
            aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
            for ad in aia.value:
                if ad.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                    resp = requests.get(ad.access_location.value, timeout=5)
                    if resp.status_code == 200:
                        try: return x509.load_der_x509_certificate(resp.content)
                        except: return None
        except: return None

    def _run_checklist_basics(self, leaf, results):
        days_left = (leaf.not_valid_after - datetime.utcnow()).days
        status = "success" if days_left > 0 else "error"
        label = f"Expires in {days_left} days." if days_left > 0 else f"Expired {abs(days_left)} days ago."
        results["checklist"].append({"label": label, "status": status})

        sans = self._get_sans(leaf)
        if self._check_hostname(self.hostname, sans):
            results["checklist"].append({"label": f"Hostname ({self.hostname}) matches certificate.", "status": "success"})
        else:
            results["checklist"].append({"label": "Hostname mismatch.", "status": "error"})

    def _get_sans(self, cert):
        try:
            ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            return ext.value.get_values_for_type(x509.DNSName)
        except:
            cn = self._get_name_attr(cert.subject, NameOID.COMMON_NAME)
            return [cn] if cn != "Unknown" else []

    def _check_hostname(self, host, sans):
        for san in sans:
            s, h = san.lower(), host.lower()
            if s == h: return True
            if s.startswith("*.") and h.endswith(s[1:]) and h.count('.') == s.count('.'): return True
        return False

    def _parse_crypto_cert(self, cert):
        fp = cert.fingerprint(hashes.SHA256()).hex().upper()
        fp = ":".join(fp[i:i+2] for i in range(0, len(fp), 2))
        return {
            "common_name": self._get_name_attr(cert.subject, NameOID.COMMON_NAME),
            "organization": self._get_name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
            "issuer": self._get_name_attr(cert.issuer, NameOID.COMMON_NAME),
            "issuer_org": self._get_name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
            "valid_from": cert.not_valid_before.isoformat(),
            "valid_to": cert.not_valid_after.isoformat(),
            "serial_number": hex(cert.serial_number).upper().replace('0X', ''),
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint_sha256": fp,
            "sans": self._get_sans(cert)
        }

    def _get_name_attr(self, name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else "Unknown"
