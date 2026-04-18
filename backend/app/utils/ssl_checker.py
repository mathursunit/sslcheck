import socket
import ssl
from datetime import datetime
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

class SSLChecker:
    def __init__(self, hostname: str, port: int = 443):
        self.hostname = hostname
        self.port = port

    def get_cert_details(self) -> Dict:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE  # User wants to check even if invalid
            
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if not cert_bin:
                        return {"error": "No certificate received from server"}
                    
                    # Note: In Python 3.9, the standard ssl lib doesn't easily return the full chain
                    # until the 'get_verified_chain' in 3.10. We parse the leaf for now.
                    leaf_cert = x509.load_der_x509_certificate(cert_bin)
                    
                    details = {
                        "hostname": self.hostname,
                        "port": self.port,
                        "is_valid": False,
                        "chain": [self._parse_crypto_cert(leaf_cert)],
                        "errors": []
                    }
                    
                    # Basic Validation
                    now = datetime.utcnow()
                    if now < leaf_cert.not_valid_before:
                        details["errors"].append("Certificate is not yet valid")
                    if now > leaf_cert.not_valid_after:
                        details["errors"].append("Certificate has expired")
                    
                    details["is_valid"] = len(details["errors"]) == 0
                    return details

        except Exception as e:
            return {"error": f"Prober Error: {type(e).__name__}: {str(e)}"}

    def _parse_crypto_cert(self, cert: x509.Certificate) -> Dict:
        subject = cert.subject
        issuer = cert.issuer
        
        # Helper to convert Name to Dict
        def name_to_dict(name):
            return {attr.oid._name: attr.value for attr in name}

        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_sha256 = ":".join(fingerprint_sha256[i:i+2] for i in range(0, len(fingerprint_sha256), 2))

        # Handle CN specifically if available
        subject_dict = name_to_dict(subject)
        issuer_dict = name_to_dict(issuer)
        
        # Add 'CN' key if commonName exists
        if 'commonName' in subject_dict:
            subject_dict['CN'] = subject_dict['commonName']
        if 'commonName' in issuer_dict:
            issuer_dict['CN'] = issuer_dict['commonName']

        return {
            "subject": subject_dict,
            "issuer": issuer_dict,
            "version": cert.version.name,
            "serial_number": cert.serial_number,
            "not_before": cert.not_valid_before.isoformat(),
            "not_after": cert.not_valid_after.isoformat(),
            "is_expired": datetime.utcnow() > cert.not_valid_after,
            "signature_algorithm": cert.signature_algorithm_oid._name,
            "fingerprint_sha256": fingerprint_sha256
        }
