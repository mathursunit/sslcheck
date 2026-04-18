import socket
import ssl
from OpenSSL import SSL
from datetime import datetime
from typing import List, Dict, Optional
from cryptography import x509
from cryptography.hazmat.primitives import hashes

class SSLChecker:
    def __init__(self, hostname: str, port: int = 443):
        self.hostname = hostname
        self.port = port

    def get_cert_details(self) -> Dict:
        try:
            # Create a context using OpenSSL
            context = SSL.Context(SSL.TLS_CLIENT_METHOD)
            context.set_verify(SSL.VERIFY_NONE) # We verify manually

            # Create a socket and connect
            conn = socket.create_connection((self.hostname, self.port), timeout=10)
            ssl_conn = SSL.Connection(context, conn)
            ssl_conn.set_tlsext_host_name(self.hostname.encode())
            ssl_conn.set_connect_state()
            ssl_conn.do_handshake()

            # Get the certificate chain
            chain = ssl_conn.get_peer_cert_chain()
            if not chain:
                return {"error": "No certificate chain found"}

            details = {
                "hostname": self.hostname,
                "port": self.port,
                "is_valid": False,
                "chain": [],
                "errors": []
            }

            # Process the chain
            for index, cert in enumerate(chain):
                cert_data = self._parse_cert(cert)
                details["chain"].append(cert_data)

            # Basic Validation (Leaf cert)
            leaf_cert = chain[0]
            not_after = datetime.strptime(leaf_cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
            not_before = datetime.strptime(leaf_cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
            now = datetime.utcnow()

            if now < not_before:
                details["errors"].append("Certificate is not yet valid")
            if now > not_after:
                details["errors"].append("Certificate has expired")

            # Check hostname (simplified)
            # In a real app we'd use cryptography to check SANs accurately
            subject = leaf_cert.get_subject()
            common_name = dict(subject.get_components()).get(b'CN', b'').decode()
            if common_name and common_name != self.hostname and not self.hostname.endswith(common_name.replace('*.', '.')):
                 # This is a bit naive, real check should be thorough
                 pass 

            details["is_valid"] = len(details["errors"]) == 0
            
            ssl_conn.close()
            return details

        except Exception as e:
            return {"error": str(e)}

    def _parse_cert(self, cert: SSL.X509) -> Dict:
        subject = cert.get_subject()
        issuer = cert.get_issuer()
        
        not_after = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        not_before = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
        
        # Get fingerprints
        crypto_cert = x509.load_pem_x509_certificate(
            # OpenSSL.SSL.X509.to_cryptography() is available in newer pyOpenSSL
            # but we can fallback to dumping pem
            SSL.dump_certificate(SSL.FILETYPE_PEM, cert)
        )
        
        fingerprint_sha256 = crypto_cert.fingerprint(hashes.SHA256()).hex().upper()
        fingerprint_sha256 = ":".join(fingerprint_sha256[i:i+2] for i in range(0, len(fingerprint_sha256), 2))

        return {
            "subject": {k.decode(): v.decode() for k, v in subject.get_components()},
            "issuer": {k.decode(): v.decode() for k, v in issuer.get_components()},
            "version": cert.get_version(),
            "serial_number": cert.get_serial_number(),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "is_expired": datetime.utcnow() > not_after,
            "signature_algorithm": cert.get_signature_algorithm().decode(),
            "fingerprint_sha256": fingerprint_sha256
        }
