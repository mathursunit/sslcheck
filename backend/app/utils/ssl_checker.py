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
        self.trace = []

    def _log(self, message: str):
        self.trace.append({
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "message": message
        })

    def get_details(self) -> Dict:
        self._log(f"Starting analysis for {self.hostname}...")
        results = {
            "hostname": self.hostname,
            "ip": None,
            "geo": {"country": "Unknown", "city": "Unknown", "isp": "Unknown", "is_cdn": False},
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
            "trace": self.trace,
            "is_valid": False
        }

        try:
            # 1. IP & GEO Lookup
            self._log("Resolving DNS records...")
            try:
                results["ip"] = socket.gethostbyname(self.hostname)
                results["checklist"].append({"label": f"{self.hostname} resolves to {results['ip']}", "status": "success"})
                self._log(f"IP found: {results['ip']}")
                
                # Geo Lookup
                self._log("Fetching Geo-location and ISP data...")
                geo_resp = requests.get(f"http://ip-api.com/json/{results['ip']}?fields=status,country,city,isp,org,as", timeout=3)
                if geo_resp.status_code == 200:
                    geo_data = geo_resp.json()
                    results["geo"] = {
                        "country": geo_data.get("country", "Unknown"),
                        "city": geo_data.get("city", "Unknown"),
                        "isp": geo_data.get("isp", "Unknown"),
                        "as": geo_data.get("as", "Unknown"),
                        "is_cdn": any(x in (geo_data.get("isp", "") + geo_data.get("org", "")).lower() for x in ["cloudflare", "akamai", "fastly", "amazon", "google", "microsoft"])
                    }
                    self._log(f"Location: {results['geo']['city']}, {results['geo']['country']} | ISP: {results['geo']['isp']}")
            except:
                results["checklist"].append({"label": f"Could not resolve {self.hostname}", "status": "error"})

            # 2. CAA Records
            self._log("Checking CAA (Certificate Authority Authorization) records...")
            self._check_caa(results)

            # 3. HTTP Layer
            self._log("Initiating HTTP/HTTPS header check...")
            self._check_hsts(results)

            # 4. Deep Handshake
            self._log("Performing deep TLS handshake and cipher negotiation...")
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
                    self._log(f"Protocol: {ssock.version()} | Cipher: {cipher[0]} ({cipher[2]} bits)")
                    
                    self._log("Extracting and parsing X.509 certificate chain...")
                    cert_bin = ssock.getpeercert(binary_form=True)
                    leaf_cert = x509.load_der_x509_certificate(cert_bin)
                    
                    self._log("Discovering certificate authority chain (AIA)...")
                    self._process_chain(leaf_cert, results)
                    self._run_checklist_basics(leaf_cert, results)

            # 5. Protocol Probing
            self._log("Probing for legacy protocol support (TLS 1.0, 1.1)...")
            results["protocols"] = self._probe_protocols()

            # 6. Final Grading
            self._log("Calculating final security grade...")
            results["security_grade"] = self._calculate_grade(results)
            results["is_valid"] = all(item["status"] == "success" for item in results["checklist"] if "HSTS" not in item["label"])
            self._log("Analysis complete.")
            
            return results

        except Exception as e:
            self._log(f"FATAL ERROR: {str(e)}")
            return {"error": str(e), "trace": self.trace}

    def _check_caa(self, results):
        try:
            answers = dns.resolver.resolve(self.hostname, 'CAA')
            for rdata in answers:
                results["caa_data"]["records"].append(str(rdata))
            results["caa_data"]["exists"] = len(results["caa_data"]["records"]) > 0
            if results["caa_data"]["exists"]:
                results["checklist"].append({"label": "CAA security policy detected.", "status": "success"})
                self._log(f"Found {len(results['caa_data']['records'])} CAA records.")
            else:
                results["checklist"].append({"label": "No CAA policy found.", "status": "info"})
        except: pass

    def _check_hsts(self, results):
        try:
            self._log("Checking for Strict-Transport-Security (HSTS) headers...")
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}
            resp = requests.get(f"https://{self.hostname}", timeout=5, verify=False, allow_redirects=True, headers=headers)
            results["server_type"] = resp.headers.get("Server", "Unknown")
            hsts = resp.headers.get("Strict-Transport-Security")
            if hsts:
                results["hsts_info"]["enabled"] = True
                self._log("HSTS header found.")
            else:
                self._log("HSTS header missing. Checking Chrome Preload List...")
                p_resp = requests.get(f"https://hstspreload.org/api/v2/status?domain={self.hostname}", timeout=3)
                if p_resp.status_code == 200 and p_resp.json().get("status") == "preloaded":
                    results["hsts_info"]["enabled"] = True
                    results["hsts_info"]["preloaded"] = True
                    self._log("Domain is on the HSTS Preload List.")
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
